#!/usr/bin/env python3

import sys
import json
import os
import stat
import subprocess
from pathlib import Path, PureWindowsPath
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import time
import hashlib
import re
import shlex
import tempfile
import platform
import shutil
import uuid
from urllib.parse import unquote, urlparse, urlsplit, urlunsplit


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
    'apply_patch': 'Edit',
}
# Native (non-MCP) Augment tools whose family is a file operation — used to gate
# the policy-cache "tools_to_check" fast path, mirroring claude-code's
# NATIVE_FILE_TOOLS. Expressed in Augment vocab. remove-files is deliberately
# EXCLUDED: it is a destructive delete that must always reach the gateway, so it
# lives only in ALLOWED_NON_MCP_HOOK_NAMES (never eligible for the fast path).
NATIVE_FILE_TOOLS = {'str-replace-editor', 'save-file', 'view', 'read-file', 'apply_patch'}
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
ALLOWED_NON_MCP_HOOK_NAMES = ['launch-process', 'str-replace-editor', 'save-file', 'view', 'read-file', 'remove-files', 'apply_patch']
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

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# discovery runs from the locally installed binary instead of a GitHub-fetched
# install.sh. UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without
# freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

_cached_api_key = None
_cached_hook_sha = None
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


# Read cap for the content hash. It must equal the discovery scanner's own cap
# (MAX_CONFIG_FILE_SIZE), because the hash below has to byte-match what the
# scanner reports for the same file — a drift here silently stops a reported
# hash from ever matching a discovered body.
SKILL_CONTENT_HASH_MAX_BYTES = 50 * 1024


def _skill_content_hash(skill_path):
    """SHA256 identity of the SKILL.md a run used, so the backend can tie the
    run to an exact discovered body. The recipe mirrors the scanner exactly:
    ``sha256("<file_name>:<content>")`` where content is read the same way the
    scanner reads it — ``read_text`` (which folds CRLF to LF) up to the cap, and
    a byte-truncated read only above it. None when the file cannot be read."""
    try:
        path = Path(skill_path)
        if path.stat().st_size > SKILL_CONTENT_HASH_MAX_BYTES:
            with open(path, 'rb') as handle:
                content = handle.read(SKILL_CONTENT_HASH_MAX_BYTES).decode('utf-8', errors='replace')
        else:
            content = path.read_text(encoding='utf-8', errors='replace')
        return hashlib.sha256(('%s:%s' % (path.name, content)).encode('utf-8')).hexdigest()
    except Exception:
        return None


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
        'content_hash': _skill_content_hash(path),
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


def _hook_sha():
    """Hash of the running file, so a report names the hook version that made it."""
    global _cached_hook_sha
    if _cached_hook_sha is None:
        try:
            _cached_hook_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]
        except Exception:
            _cached_hook_sha = 'unknown'
    return _cached_hook_sha


def _emit(text: str) -> bool:
    """Write a hook response line to stdout, treating a closed reader pipe as a
    benign no-op. The host may close the read end (timeout, cancel, session end)
    before we flush; that is not a hook error. False means the host was no longer
    listening, so the caller can tell a dropped allow from a dropped block."""
    try:
        print(text, flush=True)
        return True
    except (BrokenPipeError, OSError):
        # dup2 devnull over the fd in place, so the wrapper's buffered bytes and exit-time flush drain silently.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            # No usable fd (tests, detached stream): swap the object instead.
            try:
                sys.stdout = open(os.devnull, "w")
            except Exception:
                pass
        return False


def _read_stdin() -> Optional[str]:
    """None when the host's stdin pipe is already gone: same benign teardown as _emit."""
    try:
        return sys.stdin.read().strip()
    except OSError:
        return None


def _blocking_decision(response: Optional[Dict]) -> Optional[str]:
    """The verdict that gates the call, or None when the response lets it run."""
    response = response or {}
    if response.get('decision') == 'block':
        return 'block'
    decision = (response.get('hookSpecificOutput') or {}).get('permissionDecision')
    return decision if decision in ('deny', 'ask') else None


def _report_undelivered(hook_event_name: str, response: Dict) -> None:
    decision = _blocking_decision(response)
    if decision:
        log_error("verdict undelivered: event=%s decision=%s" % (hook_event_name, decision),
                  'undelivered_verdict')


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
            'hook_sha': _hook_sha(),
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


def get_unbound_attribution_enabled() -> bool:
    """Read the org's Unbound attribution setting from cache, defaulting to off. Ignores TTL."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return False
    return cache.get('unbound_attribution_enabled') is True


def _attribution_footer(trace_id: Optional[str] = None) -> str:
    """Footer closing a block shown to the user; no ID when no gateway saw the decision."""
    if trace_id:
        return '\n\nEnforced by Unbound · Trace ID ' + trace_id
    return '\n\nEnforced by Unbound'


def _split_attribution_footer(reason: str, trace_id: Optional[str] = None) -> Tuple[str, str]:
    """(reason without its trailing footer, footer), so the footer can be shown last."""
    footer = _attribution_footer(trace_id)
    if reason.endswith(footer):
        return reason[:-len(footer)], footer
    return reason, ''


def get_repo_policies() -> List[Dict]:
    """Repo-scope policies from cache, [] if absent; a stale cache still applies."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return []
    policies = cache.get('repo_policies')
    return policies if isinstance(policies, list) else []


def save_policy_cache(tools_to_check: Optional[List[str]] = None, policy_check_failure_action: Optional[str] = None, repo_policies: Optional[List[Dict]] = None, unbound_attribution_enabled: Optional[bool] = None):
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
        if not isinstance(unbound_attribution_enabled, bool):
            unbound_attribution_enabled = prior.get('unbound_attribution_enabled') is True
        cache = {
            'last_synced': _utc_now_z(),
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
            'repo_policies': repo_policies,
            'unbound_attribution_enabled': unbound_attribution_enabled,
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
        or 'unbound_attribution_enabled' in api_response
    ):
        save_policy_cache(
            tools_to_check=api_response.get('tools_to_check'),
            policy_check_failure_action=api_response.get('policy_check_failure_action'),
            repo_policies=api_response.get('repo_policies'),
            unbound_attribution_enabled=api_response.get('unbound_attribution_enabled'),
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
    unbound_trace_id: str = '',
) -> None:
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
        'requestId': request_id,
        'escalatedAdminContact': escalated_admin_contact,
        'unboundTraceId': unbound_trace_id,
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
    # The gateway logged this hold under a trace ID; the retry's local verdicts reuse it.
    unbound_trace_id = api_response.get('unbound_trace_id') or ''
    if unbound_trace_id:
        reason += _attribution_footer(unbound_trace_id)

    _set_approval_marker(
        approval_key,
        policy_ids,
        application_id,
        request_id=request_id,
        escalated_admin_contact=admin_contact,
        unbound_trace_id=unbound_trace_id,
    )
    # WARN/approval-required is delegated to the native toolPermissions ask-user
    # layer; the approval poll flow still surfaces a deny so the agent retries.
    return transform_response_for_claude({
        'decision': 'deny',
        'reason': reason,
        'unbound_trace_id': unbound_trace_id,
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
    # Gateway may convert WARN->deny via org setting; map ASK->permissionDecision 'ask' once Augment ships ask/allow rendering.
    if decision == 'deny':
        # Augment renders ONLY permissionDecisionReason on a PreToolUse deny, so
        # merge any additionalContext (our deny/block-failure responses put
        # agent-facing instructions there, e.g. "do not attempt workarounds")
        # into the reason or it would be dropped. Trim/skip when either side is
        # empty so we never emit a stray leading/trailing separator.
        additional_context = (api_response.get('additionalContext') or '').strip()
        reason_text = (reason or '').strip()
        # The attribution footer must be the last thing the user reads, after the context.
        reason_text, footer = _split_attribution_footer(reason_text, api_response.get('unbound_trace_id'))
        if additional_context and reason_text:
            decision_reason = reason_text + '\n\n' + additional_context
        else:
            decision_reason = reason_text or additional_context
        decision_reason += footer
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


_HOOK_SCRIPT_RUNTIMES = {
    'node', 'nodejs', 'bun', 'deno', 'python', 'python2', 'python3', 'py',
    'ruby', 'dart', 'php', 'perl', 'rscript',
}
_HOOK_SCRIPT_EXT_RE = re.compile(r'\.(sh|py|js|cjs|mjs|ts|tsx|rb|php|dart)$', re.IGNORECASE)
_HOOK_MAX_SCRIPT_BYTES = 256 * 1024

def _hook_command_basename(command: str) -> str:
    base = re.split(r'[\\/]', (command or '').strip())[-1]
    return re.sub(r'\.(exe|cmd|bat|com)$', '', base.lower())


def _hook_looks_like_path(value: str) -> bool:
    v = (value or '').strip().strip('"\'')
    if v.startswith(('http://', 'https://', '@', 'git+')):
        return False
    # Require a script extension: matching any path-shaped arg would let a
    # crafted runtime config (e.g. `python3 /etc/passwd`) read arbitrary files.
    return bool(_HOOK_SCRIPT_EXT_RE.search(v))


def _hook_runtime_entrypoint(runtime: str, args: List) -> Optional[str]:
    """The runtime's script entrypoint: the first positional argument. A flag
    before it means we cannot tell an entrypoint from a module name or a value
    the flag consumes (`python -m pkg app.py`), so nothing is read."""
    for index, raw in enumerate(args):
        if not isinstance(raw, str):
            return None
        token = raw.strip().strip('"\'')
        if index == 0 and runtime in ('bun', 'deno', 'dart') and token == 'run':
            continue
        if token.startswith('-'):
            return None
        return token
    return None


def _hook_candidate_script(command: Optional[str], args: Optional[List]) -> Optional[str]:
    """The local script this config runs: the entrypoint argument under a runtime,
    or the command itself when it's a script file. None for packages/urls/binaries."""
    base = _hook_command_basename(command or '')
    if base in _HOOK_SCRIPT_RUNTIMES:
        candidate = _hook_runtime_entrypoint(base, args or [])
        if candidate and _hook_looks_like_path(candidate):
            return candidate
        return None
    if command and _HOOK_SCRIPT_EXT_RE.search(base):
        return command
    return None


def _hook_script_path(command: Optional[str], args: Optional[List],
                      cwd: Optional[str]) -> Optional[str]:
    """Absolute, symlink-resolved path of the local script, or None. The extension
    gate is re-applied to the resolved target so a `server.py` link pointing at a
    secret can't smuggle a non-script through it."""
    cand = _hook_candidate_script(command, args)
    if not cand:
        return None
    path = os.path.expanduser(os.path.expandvars(cand.strip().strip('"\'')))
    if '${' in path:  # an env var we couldn't expand -> can't resolve
        return None
    if not os.path.isabs(path) and cwd:
        path = os.path.join(cwd, path)
    try:
        resolved = os.path.realpath(path)
    except OSError as exc:
        log_error("mcp script fingerprint: cannot resolve %s: %s"
                  % (os.path.basename(path), type(exc).__name__), 'mcp_config')
        return None
    if not _HOOK_SCRIPT_EXT_RE.search(resolved):
        log_error("mcp script fingerprint: %s resolves to a non-script target"
                  % os.path.basename(path), 'mcp_config')
        return None
    if not os.path.isfile(resolved):
        return None
    return resolved


def _hook_read_script_bytes(path: str) -> Optional[bytes]:
    """First _HOOK_MAX_SCRIPT_BYTES bytes of a regular file, else None."""
    flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(os.open(path, flags), 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        return f.read(_HOOK_MAX_SCRIPT_BYTES)


def _compute_script_hash(command: Optional[str], args: Optional[List],
                         cwd: Optional[str]) -> Optional[str]:
    """sha256 of the local script's contents, or None when it isn't a resolvable
    local script. Matches what the backend recomputes from the uploaded body, so
    the gateway's `script:<hash>` lookup lines up with the stored fingerprint.
    Capped so all clients agree on the hash for large scripts."""
    path = _hook_script_path(command, args, cwd)
    if not path:
        return None
    try:
        data = _hook_read_script_bytes(path)
    except OSError as exc:
        log_error("mcp script fingerprint: cannot read %s: %s"
                  % (os.path.basename(path), type(exc).__name__), 'mcp_config')
        return None
    if data is None:
        log_error("mcp script fingerprint: %s is not a regular file" % os.path.basename(path), 'mcp_config')
        return None
    return hashlib.sha256(data).hexdigest()


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
VSCODE_PROVIDER_CACHE_SCOPE = 'vscode-provider-cache'
VSCODE_PROVIDER_PREFIX = 'vscode-provider:'
# A loopback address is a throwaway: the port changes on every extension
# restart, so it names nothing. A real host does, and it is what makes the same
# remote server group across every tool, so those keep the url: identity.
_VSCODE_PROVIDER_LOOPBACK_URL_RE = re.compile(
    r'https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?(?:[/?#].*)?',
    re.IGNORECASE,
)
_EXTENSION_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_PROVIDER_CONTRIBUTION_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_PROVIDER_SERVER_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,127}')

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
SMITHERY_CLI_PACKAGES = frozenset({'@smithery/cli', 'smithery'})
SMITHERY_REGISTRY_SPECS = frozenset({'@smithery/cli@latest', 'smithery@latest'})
SMITHERY_GLOBAL_FLAGS = frozenset({'--verbose', '--debug', '--json', '--table'})
# Sub-runners under npx/bunx that are not the package themselves (the real
# target -- usually a local script -- follows).
NPX_LOCAL_RUNNERS = frozenset({'tsx', 'ts-node'})
# npm/bunx subcommands that precede the actual package name.
NPM_SUBCOMMANDS = frozenset({'exec', 'run', 'run-script', 'x', 'create', 'init', 'install', 'i'})
# Python-package runners and the sub-commands that precede the package.
PYPI_RUNNERS = frozenset({'uvx', 'uv', 'pipx'})
PYPI_SUBCOMMANDS = frozenset({'run', 'tool', 'tool-run'})
NUGET_RUNNERS = frozenset({'dnx', 'dotnet'})

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
    RUNTIMES | NPM_RUNNERS | PYPI_RUNNERS | NUGET_RUNNERS
    | frozenset({'docker', 'builtin', PROMPT_SECURITY_BASENAME})
)

# Basenames too generic to identify a product -- `bin:` skips these (they
# collide across unrelated servers).
GENERIC_BIN_NAMES = frozenset({
    'mcp-server', 'mcpserver', 'mcp', 'server', 'main', 'index', 'start', 'app',
    'run', 'cli', 'bin', 'tool', 'agent', 'my-command', 'my-mcp-server', 'node-repl',
    '***',
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


def _trusted_launcher_base(command: Optional[str]) -> str:
    token = _unquote(command).strip() if command else ''
    if '/' in token or '\\' in token:
        return ''
    return _command_base(token)


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
    for arg in args:
        if not isinstance(arg, str) or not arg.startswith('@'):
            continue
        return _registry_npm_package(arg)
    return None


def _registry_npm_package(spec: str) -> Optional[str]:
    token = _unquote(spec).strip()
    if token.startswith('@'):
        version_at = token.find('@', 1)
        package = token if version_at == -1 else token[:version_at]
        selector = None if version_at == -1 else token[version_at + 1:]
        package_pattern = r'@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*'
    else:
        package, separator, selector = token.partition('@')
        selector = selector if separator else None
        package_pattern = r'[a-z0-9][a-z0-9._-]*'
    if not re.fullmatch(package_pattern, package, re.IGNORECASE):
        return None
    if selector is not None and (
        selector.startswith('.')
        or not re.fullmatch(r'[a-z0-9*^~<>=.+_-]+', selector, re.IGNORECASE)
    ):
        return None
    return package.lower()


def _smithery_server_identity(value: str) -> Optional[str]:
    target = _unquote(value).strip()
    if target.startswith('@'):
        target = target[1:]
    pattern = r'[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?'
    return target.lower() if re.fullmatch(pattern, target, re.IGNORECASE) else None


def _smithery_command_target(tokens: List[str]) -> Optional[str]:
    while tokens and str(tokens[0]).lower() in SMITHERY_GLOBAL_FLAGS:
        tokens = tokens[1:]
    if tokens and str(tokens[0]).lower() == 'mcp':
        tokens = tokens[1:]
        while tokens and str(tokens[0]).lower() in SMITHERY_GLOBAL_FLAGS:
            tokens = tokens[1:]
    if not tokens or str(tokens[0]).lower() != 'run':
        return None

    target = None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            return None
        lower = token.lower()
        if lower in {'--config', '--key'}:
            if (
                index + 1 >= len(tokens)
                or not isinstance(tokens[index + 1], str)
                or tokens[index + 1].startswith('-')
            ):
                return None
            index += 2
            continue
        if any(lower.startswith(f'{flag}=') for flag in ('--config', '--key')):
            if not token.partition('=')[2]:
                return None
            index += 1
            continue
        if token.startswith('-') or target is not None:
            return None
        target = _smithery_server_identity(token)
        if target is None:
            return None
        index += 1
    return target


def _smithery_run_target(
    args: List[str],
    command_base: str,
) -> Optional[str]:
    if command_base not in {'npx', 'npm', 'cmd'}:
        return None
    if command_base == 'cmd' and any(
        isinstance(arg, str) and re.search(r'[&|<>^\r\n]', arg)
        for arg in args
    ):
        return None

    for index, arg in enumerate(args):
        if (
            not isinstance(arg, str)
            or _unquote(arg).strip().lower() not in SMITHERY_REGISTRY_SPECS
        ):
            continue
        prefix_tokens = []
        for prefix_arg in args[:index]:
            if not isinstance(prefix_arg, str):
                return None
            prefix_tokens.append(_unquote(prefix_arg).lower())

        if command_base == 'npx':
            if any(token not in {'-y', '--yes'} for token in prefix_tokens):
                return None
        elif command_base == 'npm':
            if prefix_tokens not in (['exec', '--'], ['x', '--']):
                return None
        else:
            runner_positions = [
                offset for offset, token in enumerate(prefix_tokens)
                if token in {'npx', 'npx.cmd'}
            ]
            if len(runner_positions) != 1:
                return None
            runner_index = runner_positions[0]
            shell_prefix = prefix_tokens[:runner_index]
            runner_flags = prefix_tokens[runner_index + 1:]
            if (
                '/c' not in shell_prefix
                or any(token not in {'/c', '/d', '/s'} for token in shell_prefix)
                or any(token not in {'-y', '--yes'} for token in runner_flags)
            ):
                return None
        target = _smithery_command_target(args[index + 1:])
        if target is None:
            return None
        return target
    return None


def _nuget_package(base: str, args: List[str]) -> Optional[str]:
    if base == 'dnx':
        tokens = args
    elif base == 'dotnet' and args and str(args[0]).lower() == 'dnx':
        tokens = args[1:]
    elif (
        base == 'dotnet'
        and len(args) >= 2
        and str(args[0]).lower() == 'tool'
        and str(args[1]).lower() in {'exec', 'execute'}
    ):
        tokens = args[2:]
    else:
        return None

    if any(
        isinstance(arg, str)
        and (
            arg.lower() == '--configfile'
            or arg.lower().startswith('--configfile=')
            or arg.lower().startswith('--configfile:')
            or arg.lower() == '--add-source'
            or arg.lower().startswith('--add-source=')
            or arg.lower().startswith('--add-source:')
        )
        for arg in tokens
    ):
        return None

    source_flags = {'--source', '-s'}
    source_seen = False
    for index, arg in enumerate(tokens):
        if not isinstance(arg, str):
            continue
        if arg == '--':
            break
        value = None
        if arg.lower() in source_flags:
            value = tokens[index + 1] if index + 1 < len(tokens) else None
        elif any(
            arg.lower().startswith((f'{flag}=', f'{flag}:'))
            for flag in source_flags
        ):
            value = re.split(r'[=:]', arg, maxsplit=1)[1]
        if value is None:
            continue
        source_seen = True
        if not isinstance(value, str):
            return None
        parsed = urlparse(_unquote(value))
        if parsed.scheme not in {'http', 'https'} or parsed.hostname not in {
            'api.nuget.org', 'nuget.org', 'www.nuget.org',
        }:
            return None
    if not source_seen:
        return None

    value_options = {
        '--version', '--framework', '--arch', '-a', '--verbosity', '-v',
        '--configfile', '--source', '-s',
    }
    flag_options = {
        '--prerelease', '--allow-roll-forward', '--ignore-failed-sources',
        '--interactive', '--yes', '-y', '--disable-parallel', '--no-cache',
        '--no-http-cache',
    }
    candidate = None
    version = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == '--':
            if candidate is None:
                return None
            break
        if not isinstance(token, str):
            return None
        lower = token.lower()
        option = re.split(r'[=:]', lower, maxsplit=1)[0]
        has_attached_value = len(option) < len(token)
        if option in value_options:
            if option == '--version':
                value = token[len(option) + 1:] if has_attached_value else (
                    tokens[index + 1] if index + 1 < len(tokens) else None
                )
                if not isinstance(value, str) or version is not None:
                    return None
                version = _unquote(value)
            index += 1 if has_attached_value else 2
            continue
        if lower in flag_options:
            index += 1
            continue
        if token.startswith('-'):
            return None
        if candidate is not None:
            return None
        candidate = token
        index += 1
    if not isinstance(candidate, str):
        return None
    package, separator, inline_version = _unquote(candidate).partition('@')
    if separator:
        if version is not None:
            return None
        version = inline_version
    if not version or not re.fullmatch(
        r'(?:\*|[0-9][a-z0-9*.+_-]*)', version, re.IGNORECASE,
    ):
        return None
    package = package.lower()
    return package if re.fullmatch(r'[a-z0-9][a-z0-9._-]*', package) else None


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


def _npm_runner_invocation(
    command_base: str,
    args: List[str],
) -> Optional[Tuple[str, List[str]]]:
    if command_base in NPM_RUNNERS:
        return command_base, args
    if command_base == 'bun':
        if args and isinstance(args[0], str) and _unquote(args[0]).lower() == 'x':
            return command_base, args[1:]
        return None
    if command_base != 'cmd' or any(
        not isinstance(arg, str) or re.search(r'[&|<>^\r\n]', arg)
        for arg in args
    ):
        return None
    runner_positions = [
        index for index, arg in enumerate(args)
        if _trusted_launcher_base(arg) in NPM_RUNNERS | {'bun'}
    ]
    if len(runner_positions) != 1:
        return None
    runner_index = runner_positions[0]
    shell_prefix = [_unquote(arg).lower() for arg in args[:runner_index]]
    if '/c' not in shell_prefix or any(
        token not in {'/c', '/d', '/s'} for token in shell_prefix
    ):
        return None
    runner = _trusted_launcher_base(args[runner_index])
    nested_args = args[runner_index + 1:]
    if runner == 'bun':
        if not nested_args or _unquote(nested_args[0]).lower() != 'x':
            return None
        nested_args = nested_args[1:]
    return runner, nested_args


def _npm_package_before_smithery(runner: str, args: List[str]) -> Optional[str]:
    safe_flags = {'-y', '--yes', '--'}
    if runner in {'bun', 'bunx'}:
        safe_flags.update({'--bun', '--no-install', '--verbose', '--silent'})
    npm_command_seen = runner != 'npm'
    candidate = None
    for arg in args:
        if not isinstance(arg, str):
            return None
        if _registry_npm_package(arg) in SMITHERY_CLI_PACKAGES:
            break
        token = _unquote(arg)
        lower = token.lower()
        if token.startswith('-'):
            if lower not in safe_flags:
                return None
            continue
        if not npm_command_seen:
            if lower not in {'exec', 'x'}:
                return None
            npm_command_seen = True
            continue
        if _trusted_launcher_base(token) in NPM_RUNNERS | {'bun'}:
            return None
        if candidate is not None or _looks_like_local_path(token):
            return None
        candidate = token
    return candidate if npm_command_seen else None


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


def _vscode_provider_loopback_identity(
    command: Optional[str],
    url_value: Optional[str],
    args: List[str],
    additional_data: Dict[str, Any],
) -> Optional[str]:
    if (
        command
        or args
        or additional_data.get('scope') != VSCODE_PROVIDER_CACHE_SCOPE
        or not isinstance(url_value, str)
    ):
        return None
    url_match = _VSCODE_PROVIDER_LOOPBACK_URL_RE.fullmatch(url_value.strip())
    if not url_match:
        return None
    # Five digits can still exceed a port; urlparse().port raises on those.
    if url_match.group(1) and int(url_match.group(1)) > 65535:
        return None
    provider_id = additional_data.get('providerId')
    provider_server_id = additional_data.get('providerServerId')
    if not isinstance(provider_id, str) or not isinstance(provider_server_id, str):
        return None
    provider_parts = provider_id.strip().split('/')
    server_parts = provider_server_id.strip().split('/')
    if (
        len(provider_parts) != 2
        or len(server_parts) != 2
        or not _EXTENSION_ID_RE.fullmatch(provider_parts[0])
        or not _PROVIDER_CONTRIBUTION_RE.fullmatch(provider_parts[1])
        or not _EXTENSION_ID_RE.fullmatch(server_parts[0])
        or not _PROVIDER_SERVER_NAME_RE.fullmatch(server_parts[1])
        or provider_parts[0].lower() != server_parts[0].lower()
    ):
        return None
    identity = f'{provider_id.strip().lower()}:{provider_server_id.strip().lower()}'
    if len(VSCODE_PROVIDER_PREFIX) + len(identity) > 500:
        return None
    return identity


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
    launcher_base = _trusted_launcher_base(command)

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
                additional_data=(
                    {}
                    if safe_additional_data.get('scope')
                    == VSCODE_PROVIDER_CACHE_SCOPE
                    else safe_additional_data
                ),
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

    vscode_provider = _vscode_provider_loopback_identity(
        command, url, safe_args, safe_additional_data,
    )
    if vscode_provider:
        return f'{VSCODE_PROVIDER_PREFIX}{vscode_provider}'

    # 1. url field -> url:<host[:port]/path>
    if url:
        identity = _extract_url_identity(url)
        if identity:
            return f'url:{identity}'

    nuget_package = _nuget_package(launcher_base, safe_args)
    if nuget_package:
        return f'nuget:{nuget_package}'

    smithery_match = _smithery_run_target(safe_args, launcher_base or '')
    if smithery_match:
        return f'smithery:{smithery_match}'
    if base == 'smithery':
        return None
    first_scoped_package = _npm_package_from_args(safe_args)
    runner_package = None
    runner_invocation = _npm_runner_invocation(launcher_base, safe_args)
    if runner_invocation is not None:
        runner, runner_args = runner_invocation
        if any(
            isinstance(arg, str)
            and _registry_npm_package(arg) in SMITHERY_CLI_PACKAGES
            for arg in runner_args
        ):
            candidate = _npm_package_before_smithery(runner, runner_args)
        else:
            candidate = _package_from_runner_args(
                runner_args,
                NPX_LOCAL_RUNNERS | NPM_SUBCOMMANDS | NPM_RUNNERS | RUNTIMES,
            )
        runner_package = _registry_npm_package(candidate) if candidate else None
    smithery_index = next((
        index for index, arg in enumerate(safe_args)
        if isinstance(arg, str)
        and _registry_npm_package(arg) in SMITHERY_CLI_PACKAGES
    ), None)
    first_scoped_index = next((
        index for index, arg in enumerate(safe_args)
        if isinstance(arg, str) and arg.startswith('@')
    ), None)
    if (
        smithery_index is not None
        and (
            first_scoped_index is None
            or first_scoped_index >= smithery_index
        )
    ):
        if launcher_base in NPM_RUNNERS | {'bun', 'cmd'}:
            if not runner_package or runner_package in SMITHERY_CLI_PACKAGES:
                return None
        first_scoped_package = None

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
    if first_scoped_package:
        return f'npm:{first_scoped_package}'

    # 5. npm package run via npx / npm / bunx (bare or quoted-scoped)
    if runner_package:
        return f'npm:{runner_package}'

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
    # Windsurf ships as Devin since the rebrand and a migrated machine keeps both
    # directories; the renamed one is listed first so the live config wins the
    # first-definition-wins merge below.
    return [base / n / 'User' for n in
            ('Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Devin', 'Windsurf')]


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


def _normalize_mcp_entry(entry: Dict, name: Optional[str] = None,
                         cwd: Optional[str] = None,
                         hash_script: bool = True) -> Optional[Dict]:
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
    if hash_script:
        script_hash = _compute_script_hash(
            out.get('command'), args if isinstance(args, list) else None, cwd)
        if script_hash:
            out['scriptHash'] = script_hash
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


def _augment_cli_servers(data):
    """The `{name: entry}` mapping out of an Augment settings file.

    Augment writes the servers three ways and only the first is wrapped.
    Precedence mirrors the discovery client, which parses the same file.
    """
    if not isinstance(data, dict):
        return {}
    wrapped = data.get('mcpServers')
    if isinstance(wrapped, dict):
        return wrapped
    advanced = data.get('augment')
    if isinstance(advanced, dict):
        advanced = advanced.get('advanced')
        if isinstance(advanced, dict) and isinstance(advanced.get('mcpServers'), dict):
            return advanced['mcpServers']
    # Unwrapped: every other settings key sits at this level too, so a value
    # counts as a server only when it carries what one is addressed by.
    return {name: value for name, value in data.items()
            if isinstance(value, dict) and ('command' in value or 'url' in value)}


def read_augment_mcp_servers(event: Dict, script_server: Optional[str] = None) -> Dict:
    """Aggregate MCP servers across all Augment surfaces into {name -> config}.
    First definition of a name wins; never raises (fail-open). Only
    `script_server` has its local script read and hashed."""
    servers = {}
    cwd = event.get('cwd')
    for path, fmt in _augment_mcp_config_sources(event):
        try:
            if not path.exists() or path.stat().st_size > _MCP_CONFIG_MAX_BYTES:
                continue
            data = json.loads(path.read_text(encoding='utf-8'))
            entries = []
            if fmt == 'vscode' and isinstance(data, list):
                entries = [(e.get('name'), e) for e in data if isinstance(e, dict)]
            elif fmt == 'cli':
                entries = list(_augment_cli_servers(data).items())
            for name, entry in entries:
                if name:
                    servers.setdefault(
                        name, _normalize_mcp_entry(
                            entry, name=name, cwd=cwd,
                            hash_script=(name == script_server)) or {})
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


AUGMENT_PLAN_CACHE_PATH = Path.home() / ".unbound" / "augment_plan.json"
AUGMENT_PLAN_TTL = 24 * 3600


def _fetch_augment_plan() -> Optional[str]:
    auggie = shutil.which('auggie')
    if not auggie:
        return None
    result = subprocess.run([auggie, 'account', 'status', '--json'],
                            capture_output=True, timeout=15)
    if result.returncode != 0:
        return None
    plan = json.loads(result.stdout).get('planName')
    return plan.strip() or None if isinstance(plan, str) else None


def _augment_plan(email: Optional[str], probe: bool) -> Optional[str]:
    """The plan, which Auggie reports only through its own CLI. It takes seconds,
    so only SessionStart (60s budget) asks; turns read the day-long cache. Never raises."""
    try:
        cached = json.loads(AUGMENT_PLAN_CACHE_PATH.read_text(encoding='utf-8'))
        if cached.get('email') == email and time.time() - cached.get('at', 0) < AUGMENT_PLAN_TTL:
            return cached.get('plan')
    except Exception:
        pass
    if not probe:
        return None
    try:
        plan = _fetch_augment_plan()
    except Exception:
        plan = None
    # A miss is cached too, or a machine without the CLI asks every turn.
    try:
        AUGMENT_PLAN_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = AUGMENT_PLAN_CACHE_PATH.parent / (".augment_plan.%d.tmp" % os.getpid())
        tmp.write_text(json.dumps({'email': email, 'plan': plan, 'at': time.time()}),
                       encoding='utf-8')
        os.replace(str(tmp), str(AUGMENT_PLAN_CACHE_PATH))
    except Exception:
        pass
    return plan


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
        identity['plan'] = _augment_plan(identity.get('user_email'), probe=False)
    except Exception:
        pass
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
        trace_id = str(uuid.uuid4()) if get_unbound_attribution_enabled() else None
        workspace_repo = _repo_gate_session_repo(event, report=True, trace_id=trace_id)
        if workspace_repo:
            return transform_response_for_claude({
                'decision': 'deny',
                'reason': _repo_gate_workspace_block_reason(workspace_repo, trace_id),
                'additionalContext': REPO_GATE_BLOCK_CONTEXT,
                'unbound_trace_id': trace_id,
            })
    gate = _repo_gate_evaluate(event)
    if gate:
        return transform_response_for_claude({
            'decision': 'deny',
            'reason': _repo_gate_block_reason(gate['repo'], gate.get('trace_id')),
            'additionalContext': REPO_GATE_BLOCK_CONTEXT,
            'unbound_trace_id': gate.get('trace_id'),
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
        mcp_server_name = mcp_tool_name = ''
        mcp_cfg = None
        mcp_metadata = event.get('mcp_metadata')
        if isinstance(mcp_metadata, dict):
            mcp_server_name = (mcp_metadata.get('mcpExecutedToolServerName') or '').strip()
            mcp_tool_name = (mcp_metadata.get('mcpExecutedToolName') or '').strip()
        if not mcp_server_name:
            r_server, r_tool, _ = resolve_augment_mcp(
                tool_name, read_augment_mcp_servers(event))
            if r_server:
                mcp_server_name, mcp_tool_name = r_server, r_tool
        if mcp_server_name:
            mcp_cfg = read_augment_mcp_servers(
                event, script_server=mcp_server_name).get(mcp_server_name)
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
            unbound_trace_id = marker_data.get('unboundTraceId')
            footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return transform_response_for_claude({'decision': 'allow'})
            elif result == 'deny':
                return transform_response_for_claude({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This command was denied via Slack.' + footer,
                    'additionalContext': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                    'unbound_trace_id': unbound_trace_id,
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
                    'reason': timeout_reason + footer,
                    'additionalContext': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                    'unbound_trace_id': unbound_trace_id,
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        # Fail-open is load-bearing: a failing/unreachable check ALLOWS. The ONLY
        # non-fail-open path is an explicit cached policy_check_failure_action of
        # 'block' (defaults to 'allow').
        if get_policy_check_failure_action() == 'block':
            footer = _attribution_footer() if get_unbound_attribution_enabled() else ''
            return transform_response_for_claude({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON + footer,
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
    # Repo/org names can contain spaces (e.g. Azure DevOps); the URL path
    # arrives percent-encoded, so decode before splitting into org/repo.
    path = unquote(path)
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


# --- Bash calls in scope for the repo gate: a segment runs a git write subcommand or writes the working tree; anything unclassifiable is not gated ---
_QUOTED_RUN_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
_SHELL_SEGMENT_SEP_RE = re.compile(r'\|\||&&|[;|&\n]')
_ENV_ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
# Wrappers that stand in front of the real command word.
_COMMAND_PREFIX_WORDS = frozenset({'sudo', 'env', 'command'})
# Creating or appending redirect and its target; `>& file` writes a file, `>&1` / `>&-` only move a descriptor; the lookbehind keeps `>>` from counting twice.
_REDIRECT_RE = re.compile(r'(?<!>)>>?(?:&(?!(?:\d+|-)(?:[\s;&|)`]|$)))?(?![&>])\s*([^\s;&|)`]*)')
# A redirect into one of these touches no file.
_DEVICE_REDIRECT_TARGETS = frozenset({'/dev/null', '/dev/stdout', '/dev/stderr', '/dev/tty'})

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

# git subcommands that change the repository; everything else (status, diff, log, fetch, config, aliases) passes.
_GIT_WRITE_SUBCOMMANDS = frozenset({
    'add', 'commit', 'push', 'pull', 'merge', 'rebase', 'cherry-pick', 'revert',
    'reset', 'checkout', 'switch', 'restore', 'tag', 'stash', 'clean', 'rm', 'mv',
    'apply', 'am',
})
# `git branch` writes only when deleting.
_GIT_BRANCH_DELETE_FLAGS = frozenset({'-d', '-D', '--delete'})
# git's own options that take the next word as their value, so `git -C dir commit` reads as `commit`.
_GIT_OPTIONS_WITH_VALUE = frozenset({'-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env', '--attr-source'})


def _mask_quoted_runs(command):
    """Blank the inside of quoted runs, preserving length; an unbalanced quote leaves its tail untouched."""
    return _QUOTED_RUN_RE.sub(
        lambda m: m.group(0)[0] + ' ' * (len(m.group(0)) - 2) + m.group(0)[0],
        command)


def _segment_words(segment):
    """A segment's words from its command word on, dropping env assignments and any sudo/env/command wrapper."""
    try:
        raw_words = shlex.split(segment)
    except ValueError:  # unbalanced quote or trailing backslash
        raw_words = segment.split()
    words = []
    for word in raw_words:
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


def _git_subcommand(words):
    """The first word after git that is not one of git's own options."""
    rest = iter(words[1:])
    for word in rest:
        if word in _GIT_OPTIONS_WITH_VALUE:
            next(rest, None)
        elif not word.startswith('-'):
            return word
    return None


def _is_git_write_command(command):
    """Whether any segment runs a git subcommand that changes the repository; False on any error."""
    try:
        if not isinstance(command, str) or 'git' not in command:
            return False
        for segment, _ in _shell_segments(command):  # unmasked, so a quoted option value resolves
            words = _segment_words(segment)
            if not words or os.path.basename(words[0]) != 'git':
                continue
            subcommand = _git_subcommand(words)
            if subcommand in _GIT_WRITE_SUBCOMMANDS:
                return True
            if subcommand == 'branch' and _GIT_BRANCH_DELETE_FLAGS.intersection(words):
                return True
        return False
    except Exception:
        return False


def _is_shell_write_command(command):
    """Whether `command` mutates the working tree: a write command word in any segment, or a redirect into a file. False on any error."""
    try:
        if not isinstance(command, str) or not command:
            return False
        masked = _mask_quoted_runs(command)
        if any(m.group(1) not in _DEVICE_REDIRECT_TARGETS for m in _REDIRECT_RE.finditer(masked)):
            return True
        for segment in _SHELL_SEGMENT_SEP_RE.split(masked):
            words = _segment_words(segment)
            if words and _segment_writes(words):
                return True
        return False
    except Exception:
        return False


# --- Repository-scope gate: blocks writes, git write subcommands and shell writes outside the org's allowed scope; Augment (https://docs.augmentcode.com/cli/hooks) has no warning phase and denies from the first violating call ---

# Write tools, git write subcommands and shell writes only; the read tools (view, read-file) are ungated, remove-files is a write, and every other shell command (ls, cat, npm test) is ungated.
_REPO_GATE_WRITE_TOOLS = frozenset({'str-replace-editor', 'save-file',
                                    'remove-files', 'apply_patch'})
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
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it runs a git write or writes a file."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_write_command(command) or _is_shell_write_command(command)
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


def _repo_gate_block_reason(repo: str, trace_id: Optional[str] = None) -> str:
    """Augment renders only permissionDecisionReason, so this carries it all."""
    reason = (
        'Blocked by organization policy. This action works in the repository '
        '"%s", which is outside your organization\'s allowed repository scope. '
        'Move this work to an in-scope repository.' % repo
    )
    return reason + _attribution_footer(trace_id) if trace_id else reason


def _repo_gate_workspace_block_reason(repo: str, trace_id: Optional[str] = None) -> str:
    """Augment renders only permissionDecisionReason, so this carries it all."""
    reason = (
        'Blocked by organization policy. This workspace is the repository "%s", '
        'which is outside your organization\'s allowed repository scope, so every '
        'tool call here is blocked. Move this work to an in-scope repository and '
        'start a new session there.' % repo
    )
    return reason + _attribution_footer(trace_id) if trace_id else reason


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
        envelope = {
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
        }
        # Only with attribution on: support finds the incident by the ID the user saw.
        if gate.get('trace_id'):
            envelope['repo_gate']['trace_id'] = gate['trace_id']
        _repo_gate_post(json.dumps(envelope), api_key)
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
        if get_unbound_attribution_enabled():
            gate['trace_id'] = str(uuid.uuid4())
        _repo_gate_report(gate, block_policies, {
            'app_label': 'augment_code',
            'session_id': event.get('session_id'),
            'tool_name': tool_name,
            'tool_input': event.get('tool_input'),
        })
        return gate
    except Exception:
        return None


def _repo_gate_session_repo(event: Dict, report: bool = False, trace_id: Optional[str] = None) -> Optional[str]:
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
            _repo_gate_report({'decision': 'deny', 'repo': repo, 'trace_id': trace_id}, block_policies, {
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


# KEEP IN SYNC: transfer resolution — byte-identical in every agent hook, here and in cursor-plugin, do not diverge.
# --- Transfer resolution: where each shell transfer went, as host and address kind only, fail-open ---

# Only these commands are ever run; everything else is refused. DNS is a resolver call, not a command.
_TRANSFER_ALLOWED_RUNS = (('ssh', '-G'),)
_TRANSFER_RUN_TIMEOUT = 5
_TRANSFER_DNS_TIMEOUT = 1.5
# Wall-clock budget for all lookups in one turn, so a slow lookup never delays the agent.
_TRANSFER_TURN_BUDGET = 10.0
_TRANSFER_MAX_ENDPOINTS = 10
# How deep substitutions and `sh -c` strings are followed.
_TRANSFER_MAX_DEPTH = 8
# How many function calls are followed in one command, so a recursive function stays cheap.
_TRANSFER_MAX_CALLS = 32
# How many words one brace expansion or curl URL glob is expanded into.
_TRANSFER_MAX_WORDS = 64
# A longer command, or one nesting compounds deeper, is skipped whole so it can't hold up the turn.
_TRANSFER_MAX_CHARS = 20000
_TRANSFER_MAX_NESTING = 100
# Wrappers that run the command after them: (short options that take a value, long ones that do, operands before it).
_TRANSFER_WRAPPERS = {
    'sudo': ('ugCDhprtTU', {'--user', '--group', '--close-from', '--chdir', '--host', '--prompt', '--role', '--type',
                            '--command-timeout', '--other-user'}, 0),
    'doas': ('uC', set(), 0),
    'env': ('uCS', {'--unset', '--chdir', '--split-string'}, 0),
    'nice': ('n', {'--adjustment'}, 0),
    'timeout': ('ks', {'--kill-after', '--signal'}, 1),
    'time': ('fo', {'--format', '--output'}, 0),
    'stdbuf': ('ioe', {'--input', '--output', '--error'}, 0),
    'ionice': ('cnp', {'--class', '--classdata', '--pid'}, 0),
    'exec': ('a', set(), 0),
    'command': ('', set(), 0),
    'builtin': ('', set(), 0),
    'nohup': ('', set(), 0),
}
# Reserved words that open, divide or close a compound command.
_TRANSFER_KEYWORDS = frozenset({'{', '}', 'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'for', 'select', 'do',
                                'done', '!', 'function', 'time'})
# Reserved words after which the next word still starts a command.
_TRANSFER_LEADING_WORDS = frozenset({'{', 'if', 'then', 'elif', 'else', 'while', 'until', 'do', '!', 'time'})
_TRANSFER_LOOPS = ('while', 'until', 'for', 'select')
_TRANSFER_DECLARES = ('declare', 'typeset', 'local', 'readonly')
_TRANSFER_SHELLS = frozenset({'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash'})
_TRANSFER_POWERSHELLS = frozenset({'powershell', 'pwsh'})
# Set in a command's env by `env -i`: nothing is inherited from the hook's environment.
_TRANSFER_CLEAN_ENV = '\0clean'
# Set after eval or source, whose text may set any variable: one not set since then is unknown.
_TRANSFER_UNKNOWN_ENV = '\0unknown'
# Stands in for a substitution's output inside a word, so no host is read from it.
_TRANSFER_SUBSTITUTED = '\0'
# Mark a word's unquoted { , and }, which bash may brace-expand, and turn them back once it has.
_TRANSFER_BRACE_MARKS = {'{': '\1', ',': '\2', '}': '\3'}
_TRANSFER_UNMARK = {1: '{', 2: ',', 3: '}'}
# Marks a quoted or escaped ~ that starts a word, which the shell leaves as it is; _transfer_tilde turns it back.
_TRANSFER_LITERAL_TILDE = '\5'
_TRANSFER_TOOLS = {
    'curl': 'curl', 'wget': 'wget', 'scp': 'scp', 'rsync': 'rsync', 'sftp': 'sftp', 'ssh': 'ssh',
    'nc': 'nc', 'ncat': 'nc', 'netcat': 'nc', 'socat': 'socat', 'http': 'httpie', 'https': 'httpie',
    'invoke-webrequest': 'powershell', 'invoke-restmethod': 'powershell', 'iwr': 'powershell', 'irm': 'powershell',
}
_TRANSFER_SENDING_METHODS = frozenset({'POST', 'PUT', 'PATCH'})
# The port a URL connects to when it names none, by scheme.
_TRANSFER_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990, 'ws': 80, 'wss': 443, 'scp': 22,
                           'sftp': 22, 'imap': 143, 'imaps': 993, 'pop3': 110, 'pop3s': 995, 'smtp': 25,
                           'smtps': 465, 'ldap': 389, 'ldaps': 636, 'dict': 2628, 'gopher': 70, 'gophers': 70,
                           'rtsp': 554, 'telnet': 23, 'tftp': 69, 'mqtt': 1883, 'smb': 445, 'smbs': 445}
# The URL schemes each tool speaks; a URL with any other reaches no host.
_TRANSFER_CURL_SCHEMES = frozenset({'dict', 'ftp', 'ftps', 'gopher', 'gophers', 'http', 'https', 'imap', 'imaps', 'ldap',
                                    'ldaps', 'mqtt', 'pop3', 'pop3s', 'rtsp', 'scp', 'sftp', 'smb', 'smbs', 'smtp',
                                    'smtps', 'telnet', 'tftp', 'ws', 'wss'})
_TRANSFER_WGET_SCHEMES = frozenset({'http', 'https', 'ftp', 'ftps'})
_TRANSFER_HTTPIE_SCHEMES = frozenset({'http', 'https'})
_TRANSFER_POWERSHELL_SCHEMES = frozenset({'http', 'https', 'ftp'})
# Options that take a value, per program; every other option is a switch.
_TRANSFER_SSH_VALUE_FLAGS = {'ssh': frozenset('BbcDEeFIiJLlmOoPpQRSWw'), 'scp': frozenset('cDFiJloPSX'),
                             'sftp': frozenset('BbcDFiJloPRSsX'), 'rsync': frozenset('efTMB@')}
# Of ssh's -o settings, only these change which host or user ssh -G resolves.
_TRANSFER_SSH_IDENTITY_OPTIONS = frozenset({'hostname', 'user', 'port', 'proxyjump', 'proxycommand'})
# A host reached through one of these is resolved by the proxy, so it is never looked up here.
# curl's proxy options and the kind of proxy each names; -x, --proxy and --preproxy name it by their URL's scheme.
_TRANSFER_CURL_PROXIES = {'-x': '', '--proxy': '', '--preproxy': '', '--socks4': 'socks4', '--socks4a': 'socks4a',
                          '--socks5': 'socks5', '--socks5-hostname': 'socks5h'}
_TRANSFER_PROXY_ENV = ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'ftp_proxy', 'FTP_PROXY', 'all_proxy',
                       'ALL_PROXY')
_TRANSFER_SSH_CONFIG_MAX_BYTES = 256 * 1024
_TRANSFER_SSH_CONFIG_MAX_FILES = 32
_TRANSFER_RSYNC_VALUE_OPTIONS = frozenset({
    '--exclude', '--include', '--filter', '--exclude-from', '--include-from', '--files-from', '--rsync-path',
    '--log-file', '--partial-dir', '--temp-dir', '--compare-dest', '--copy-dest', '--link-dest', '--backup-dir',
    '--chmod', '--chown', '--suffix', '--password-file', '--port', '--bwlimit', '--timeout', '--max-size',
    '--min-size', '--out-format', '--remote-option', '--block-size', '--modify-window'})
# curl's options that take a value (`curl --help all`), so a value is never read as a URL.
_TRANSFER_CURL_SHORT_VALUES = frozenset('ACDEFHKPQTUXYbcdemortuwxyz')
_TRANSFER_CURL_LONG_VALUES = frozenset((
    '--abstract-unix-socket --alt-svc --aws-sigv4 --cacert --capath --cert --cert-type --ciphers --config '
    '--connect-timeout --connect-to --continue-at --cookie --cookie-jar --create-file-mode --crlfile --curves --data '
    '--data-ascii --data-binary --data-raw --data-urlencode --delegation --dns-interface --dns-ipv4-addr '
    '--dns-ipv6-addr --dns-servers --doh-url --dump-header --egd-file --engine --etag-compare --etag-save '
    '--expect100-timeout --form --form-string --ftp-account --ftp-alternative-to-user --ftp-method --ftp-port '
    '--ftp-ssl-ccc-mode --happy-eyeballs-timeout-ms --haproxy-clientip --header --hostpubmd5 --hostpubsha256 --hsts '
    '--interface --ipfs-gateway --json --keepalive-time --key --key-type --krb --libcurl --limit-rate --local-port '
    '--login-options --mail-auth --mail-from --mail-rcpt --max-filesize --max-redirs --max-time --netrc-file '
    '--noproxy --oauth2-bearer --output --output-dir --parallel-max --pass --pinnedpubkey --preproxy --proto '
    '--proto-default --proto-redir --proxy --proxy-cacert --proxy-capath --proxy-cert --proxy-cert-type '
    '--proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass --proxy-pinnedpubkey '
    '--proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype --proxy-tlspassword --proxy-tlsuser --proxy-user '
    '--pubkey --quote --random-file --range --rate --referer --request --request-target --resolve --retry '
    '--retry-delay --retry-max-time --sasl-authzid --service-name --socks4 --socks4a --socks5 '
    '--socks5-gssapi-service --socks5-hostname --speed-limit --speed-time --stderr --telnet-option --tftp-blksize '
    '--time-cond --tls-max --tls13-ciphers --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii '
    '--trace-config --unix-socket --upload-file --url --url-query --user --user-agent --variable --write-out').split())
_TRANSFER_CURL_UPLOADS = frozenset({'-T', '--upload-file', '-F', '--form', '--form-string', '--json'})
_TRANSFER_CURL_BODIES = frozenset({'-d', '--data', '--data-ascii', '--data-binary', '--data-raw', '--data-urlencode'})
# The switches a --no- option turns back off, so the last of them decides.
_TRANSFER_CURL_UNDOES = {'--no-globoff': {'-g', '--globoff'}, '--no-get': {'-G', '--get'}}
_TRANSFER_WGET_SHORT_VALUES = frozenset('aABDeIilnOoPQRtTUwX')
_TRANSFER_WGET_LONG_VALUES = frozenset((
    '--output-file --append-output --execute --input-file --base --config --rejected-log --tries '
    '--retry-on-http-error --output-document --backups --timeout --dns-timeout --connect-timeout --read-timeout '
    '--wait --waitretry --bind-address --limit-rate --quota --user --password --header --compression --max-redirect '
    '--proxy-user --proxy-password --referer --save-cookies --load-cookies --post-data --post-file --method '
    '--body-data --body-file --default-page --directory-prefix --cut-dirs --level --accept --reject --accept-regex '
    '--reject-regex --regex-type --domains --exclude-domains --follow-tags --ignore-tags --include-directories '
    '--exclude-directories --user-agent --secure-protocol --certificate --certificate-type --private-key '
    '--private-key-type --ca-certificate --ca-directory --crl-file --pinnedpubkey --random-file --egd-file --ciphers '
    '--hsts-file --ftp-user --ftp-password --http-user --http-password --warc-file --warc-header --warc-max-size '
    '--warc-dedup --warc-tempdir --local-encoding --remote-encoding --restrict-file-names --prefer-family '
    '--report-speed --progress --use-askpass').split())
_TRANSFER_WGET_UPLOADS = frozenset({'--post-data', '--post-file', '--body-data', '--body-file'})
_TRANSFER_NC_SHORT_VALUES = frozenset('eGgIiMmOoPpqsTVWwXx')
_TRANSFER_NC_LONG_VALUES = frozenset((
    '--proxy --proxy-type --proxy-auth --proxy-dns --source --source-port --wait --idle-timeout --exec --sh-exec '
    '--lua-exec --output --hex-dump --allow --allowfile --deny --denyfile --max-conns --delay --ssl-cert --ssl-key '
    '--ssl-trustfile --ssl-ciphers --ssl-servername --ssl-alpn').split())
_TRANSFER_SOCAT_VALUE_OPTIONS = frozenset({'-b', '-t', '-T', '-L', '-W', '-lf', '-lp'})
_TRANSFER_HTTPIE_SHORT_VALUES = frozenset('aAoPps')
_TRANSFER_HTTPIE_LONG_VALUES = frozenset((
    '--auth --auth-type --session --session-read-only --output --print --history-print --pretty --style '
    '--format-options --response-charset --response-mime --verify --cert --cert-key --cert-key-pass --ssl --ciphers '
    '--timeout --max-redirects --max-headers --proxy --default-scheme --boundary --raw').split())
# Invoke-WebRequest and Invoke-RestMethod parameters that take no value.
_TRANSFER_PS_SWITCHES = frozenset({
    'usebasicparsing', 'usedefaultcredentials', 'proxyusedefaultcredentials', 'disablekeepalive', 'passthru',
    'skipcertificatecheck', 'skipheadervalidation', 'skiphttperrorcheck', 'allowunencryptedauthentication',
    'allowinsecureredirect', 'noproxy', 'preserveauthorizationonredirect', 'preservehttpmethodonredirect', 'resume',
    'followrellink', 'preserveheaderscase', 'verbose', 'debug', 'whatif', 'confirm'})
# Their own parameters that take a value, the common ones, and the aliases, for PowerShell's resolving of a name.
_TRANSFER_PS_OWN = _TRANSFER_PS_SWITCHES - {'verbose', 'debug', 'whatif', 'confirm'} | {
    'uri', 'method', 'body', 'headers', 'outfile', 'infile', 'contenttype', 'useragent', 'proxy', 'credential',
    'timeoutsec', 'websession', 'sessionvariable', 'form', 'maximumredirection', 'maximumretrycount',
    'retryintervalsec', 'certificatethumbprint', 'certificate', 'authentication', 'token', 'custommethod', 'sslprotocol',
    'transferencoding', 'proxycredential', 'connectiontimeoutseconds', 'operationtimeoutseconds', 'httpversion',
    'responseheadersvariable', 'statuscodevariable', 'maximumfollowrellink', 'unixsocket'}
_TRANSFER_PS_COMMON = frozenset({
    'verbose', 'debug', 'whatif', 'confirm', 'erroraction', 'warningaction', 'informationaction', 'progressaction',
    'errorvariable', 'warningvariable', 'informationvariable', 'outvariable', 'outbuffer', 'pipelinevariable'})
_TRANSFER_PS_ALIASES = {
    'vb': 'verbose', 'db': 'debug', 'wi': 'whatif', 'cf': 'confirm', 'ea': 'erroraction', 'wa': 'warningaction',
    'infa': 'informationaction', 'proga': 'progressaction', 'ev': 'errorvariable', 'wv': 'warningvariable',
    'iv': 'informationvariable', 'ov': 'outvariable', 'ob': 'outbuffer', 'pv': 'pipelinevariable',
    'cm': 'custommethod', 'sv': 'sessionvariable', 'rhv': 'responseheadersvariable'}
# Address kinds, checked in order; any other address is public.
_TRANSFER_ADDRESS_KINDS = (
    ('loopback', ('127.0.0.0/8', '0.0.0.0/32', '::1/128', '::/128')),
    ('private', ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')),
    ('link_local', ('169.254.0.0/16', 'fe80::/10')),
    ('cgnat', ('100.64.0.0/10',)),
)


def _transfer_deadline(state: Dict) -> float:
    """When this turn's lookups must stop; a caller may seed a shorter budget in state."""
    return state.setdefault('deadline', time.monotonic() + state.get('budget', _TRANSFER_TURN_BUDGET))


def _transfer_run(argv: List[str], cwd: Optional[str], state: Dict) -> Optional[str]:
    """Run one allowlisted lookup within its timeout and the turn's budget; None when refused, slow or failing. ssh -G
    is checked here, and reads only the vetted copy of its configs made here, so no call reaches it unchecked."""
    import shutil
    import tempfile
    folder = None
    try:
        if not any(tuple(argv[:len(p)]) == p for p in _TRANSFER_ALLOWED_RUNS):
            return None
        remaining = _transfer_deadline(state) - time.monotonic()
        if remaining <= 0:
            return None
        if argv[:2] == ['ssh', '-G']:
            folder, end = tempfile.mkdtemp(prefix='unbound-ssh-'), argv.index('--')
            options = _transfer_ssh_vetted(argv[2:end], cwd, folder)
            if options is None:
                return None
            argv = argv[:2] + options + argv[end:]
        result = subprocess.run(argv, cwd=cwd if cwd and os.path.isdir(cwd) else None, capture_output=True,
                                text=True, timeout=min(_TRANSFER_RUN_TIMEOUT, remaining), stdin=subprocess.DEVNULL)
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None
    finally:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


def _transfer_read_word(text: str, i: int) -> tuple:
    """(the shell word starting at i after blanks, the index after it); quotes and backslashes are undone."""
    while i < len(text) and text[i] in ' \t':
        i += 1
    word, quote = '', None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == '\\' and quote == '"' and i + 1 < len(text):
                i += 1
                word += text[i]
            else:
                word += ch
        elif ch in '\'"':
            quote = ch
        elif ch == '\\' and i + 1 < len(text):
            i += 1
            word += text[i]
        elif ch in ' \t\r\n;&|<>()':
            break
        else:
            word += ch
        i += 1
    return word, i


def _transfer_word_end(text: str, i: int) -> tuple:
    """(the index after the shell word starting at i after blanks, the $( ) and backtick bodies in it, which run);
    the index is -1 when one of them is not closed."""
    while i < len(text) and text[i] in ' \t':
        i += 1
    bodies, quote = [], None
    while i < len(text):
        ch, start = text[i], i
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == '\\':
            i += 1
        elif text.startswith('$(', i) or ch == '`':
            arithmetic = text.startswith('$((', i) and _transfer_arithmetic_end(text, i + 2) > 0
            i = _transfer_paren_end(text, i + 2) if ch == '$' else _transfer_backtick_end(text, i + 1)
            inner = _transfer_text_bodies(text[start + 3:i - 1]) if arithmetic else []
            if i < 0 or inner is None:
                return -1, bodies
            bodies += inner if arithmetic else [text[start + 2:i] if ch == '$' else text[start + 1:i]]
        elif quote == '"':
            quote = None if ch == '"' else quote
        elif ch in '\'"':
            quote = ch
        elif ch in ' \t\r\n;&|<>()':
            break
        i += 1
    return i, bodies


def _transfer_text_bodies(body: str) -> Optional[List[str]]:
    """The $( ) and backtick bodies that run when an unquoted heredoc or an arithmetic expression is expanded, those
    inside $(( )) too; quotes are plain text there and a backslash escapes. None when one is not closed."""
    bodies, i = [], 0
    while i < len(body):
        start = i
        if body[i] == '\\':
            i += 1
        elif body.startswith('$(', i) or body[i] == '`':
            arithmetic = body.startswith('$((', i) and _transfer_arithmetic_end(body, i + 2) > 0
            i = _transfer_paren_end(body, i + 2) if body[i] == '$' else _transfer_backtick_end(body, i + 1)
            inner = _transfer_text_bodies(body[start + 3:i - 1]) if arithmetic else []
            if i < 0 or inner is None:
                return None
            bodies += inner if arithmetic else [body[start + 2:i] if body[start] == '$' else body[start + 1:i]]
        i += 1
    return bodies


def _transfer_expanded(body: str) -> str:
    """An unquoted heredoc's text as the shell hands it on: each $( ), $(( )) and backtick output unknown, and a
    backslash before $, `, \\ or a newline removed."""
    out, i = [], 0
    while i < len(body):
        start = i
        if body[i] == '\\' and body[i + 1:i + 2] in ('$', '`', '\\', '\n'):
            out.append(body[i + 1] if body[i + 1] != '\n' else '')
            i += 2
            continue
        if body.startswith('$(', i) or body[i] == '`':
            i = _transfer_paren_end(body, i + 2) if body[i] == '$' else _transfer_backtick_end(body, i + 1)
            if i < 0:
                return body[:start] + _TRANSFER_SUBSTITUTED
            out.append(_TRANSFER_SUBSTITUTED)
        else:
            out.append(body[i])
        i += 1
    return ''.join(out)


class _TransferStdin(str):
    """A redirection that feeds a heredoc's or here-string's text: 'file' to the fds, with the text as text, for a
    shell or tool that reads its script or config from stdin."""
    text = None


def _transfer_arithmetic_parts(text: str) -> Optional[List[str]]:
    """An arithmetic for header's start, test and step, split at the ; outside any substitution; None if not three."""
    parts, start, i = [], 0, 0
    while i < len(text):
        if text.startswith('$(', i) or text[i] == '`':
            i = _transfer_paren_end(text, i + 2) if text[i] == '$' else _transfer_backtick_end(text, i + 1)
            if i < 0:
                return None
        elif text[i] == ';':
            parts, start = parts + [text[start:i]], i + 1
        i += 1
    return parts + [text[start:]] if len(parts) == 2 else None


_TRANSFER_ARITHMETIC_ENDS: Dict[str, Dict[int, int]] = {}


def _transfer_arithmetic_end(text: str, i: int) -> int:
    """For a (( whose second ( is at i, the index of the last ) of the )) that closes it, past quotes, backticks and
    $( ). -1 when the ) matching that ( is not followed by another: bash and zsh then read ( ( … ) … ) as commands."""
    ends = _TRANSFER_ARITHMETIC_ENDS.get(text)
    if ends is None:  # kept for the last text only: the scans nest, and each would otherwise be repeated
        _TRANSFER_ARITHMETIC_ENDS.clear()
        ends = _TRANSFER_ARITHMETIC_ENDS[text] = {}
    if i not in ends:
        ends[i] = _transfer_arithmetic_scan(text, i)
    return ends[i]


def _transfer_arithmetic_scan(text: str, i: int) -> int:
    depth, quote = 0, None
    while i < len(text):
        ch = text[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == '\\':
            i += 1
        elif ch == '`' and _transfer_backtick_end(text, i + 1) > 0:
            i = _transfer_backtick_end(text, i + 1)
        elif text.startswith('$(', i):
            i = _transfer_paren_end(text, i + 2)
            if i < 0:
                return -1
        elif quote == '"':
            quote = None if ch == '"' else quote
        elif ch in '\'"':
            quote = ch
        elif ch in '()':
            depth += 1 if ch == '(' else -1
            if depth == 0:
                return i + 1 if text[i + 1:i + 2] == ')' else -1
        i += 1
    return -1


def _transfer_paren_end(text: str, i: int) -> int:
    """The index of the ) that closes a ( just before i, past quotes, backticks, nested parentheses, the ) after a case
    pattern, comments and heredoc bodies; for a ((, the end of its arithmetic when it is one. -1 if none closes it."""
    arithmetic = _transfer_arithmetic_end(text, i) if text[i - 1:i + 1] == '((' else -1
    if arithmetic > 0:
        return arithmetic
    depth, quote, cases, word, last, at_start, heredocs = 1, None, [], '', '', True, []
    while i < len(text):
        ch = text[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == '\\':
            i, word = i + 1, word + '\0'
        elif ch == '`' and _transfer_backtick_end(text, i + 1) > 0:
            i, word = _transfer_backtick_end(text, i + 1), word + '\0'
        elif quote == '"':
            if ch == '"':
                quote = None
            elif text.startswith('$(', i):
                i = _transfer_paren_end(text, i + 2)
                if i < 0:
                    return -1
        elif ch in '\'"':
            quote, word = ch, word + '\0'
        elif text.startswith('((', i) and (at_start or last == 'for') and \
                (word in ('', 'for') or word in _TRANSFER_LEADING_WORDS) and _transfer_arithmetic_end(text, i + 1) > 0:
            # An arithmetic command inside: a # or << there is arithmetic, not a comment or heredoc.
            i, word = _transfer_arithmetic_end(text, i + 1), word + '\0'
        elif text.startswith('$((', i) and _transfer_arithmetic_end(text, i + 2) > 0:
            i, word = _transfer_arithmetic_end(text, i + 2), word + '\0'  # likewise an arithmetic expansion
        elif ch == '#' and not word:
            i = text.find('\n', i) - 1  # a comment runs to the end of its line
            if i < 0:
                return -1
        elif ch not in ' \t\r\n;&|()<>':
            word += ch
        else:
            if word:
                at_start, last = _transfer_case_word(word, at_start, cases), word
            word = ''
            if text.startswith('<<<', i):
                i += 2
            elif text.startswith('<<', i):
                delimiter, end = _transfer_read_word(text, i + (3 if text.startswith('<<-', i) else 2))
                heredocs.append((delimiter, text.startswith('<<-', i)))
                i = end - 1
            elif cases and cases[-1] == 'pattern' and ch in '()':
                cases[-1], at_start = ('body', True) if ch == ')' else ('pattern', at_start)  # ( may open a pattern
            elif ch in '()':
                depth += 1 if ch == '(' else -1
                if depth == 0:
                    return i
            if ch in ';&|\n(':
                at_start = True
            if cases and cases[-1] == 'body' and text.startswith((';;', ';&'), i):
                cases[-1], i = 'pattern', i + (2 if text.startswith(';;&', i) else 1)
            if ch == '\n':
                i = _transfer_heredocs_end(text, i, heredocs)
        i += 1
    return -1


def _transfer_heredocs_end(text: str, i: int, heredocs: List[tuple]) -> int:
    """Past the bodies of the heredocs pending at the newline at i: the index of the last body's delimiter line end."""
    while heredocs:
        delimiter, strip_tabs = heredocs.pop(0)
        while i + 1 < len(text):
            end = text.find('\n', i + 1)
            line = text[i + 1:] if end < 0 else text[i + 1:end]
            i = len(text) - 1 if end < 0 else end
            if (line.lstrip('\t') if strip_tabs else line) == delimiter:
                break
    return i


def _transfer_case_word(word: str, at_start: bool, cases: List[str]) -> bool:
    """Follow a word through the case commands open in a $( ): case opens one, in starts its patterns, esac ends it;
    whether the next word starts a command."""
    if word == 'case' and at_start:
        cases.append('head')
    elif word == 'in' and cases and cases[-1] == 'head':
        cases[-1] = 'pattern'
    elif word == 'esac' and cases and cases[-1] != 'head':
        cases.pop()
    else:
        return word in _TRANSFER_LEADING_WORDS
    return False


def _transfer_backtick_end(text: str, i: int) -> int:
    """The index of the backtick that closes one just before i; -1 when none does."""
    while i < len(text):
        if text[i] == '`':
            return i
        i += 2 if text[i] == '\\' else 1
    return -1


class _TransferLexer:
    """Reads a command into items in the order they run: ('cmd', argv, operator before, operator after, redirections as
    (fd, 'file' | 'null' | fd copied)), or a '(', '$(', ')', 'func', 'case', 'arm' or 'esac' marker around them."""

    def __init__(self, text: str, depth: int = 0):
        self.text, self.depth, self.i, self.quote = text, depth, 0, None
        self.items, self.argv, self.word, self.in_word = [], [], '', False
        self.before, self.io, self.heredocs, self.case = '', [], [], []
        self.param, self.dollar, self.failed, self.ends = 0, -1, False, {}

    def read(self) -> Optional[List[tuple]]:
        """The items, or None when the command can't be read the way the shell reads it."""
        if self.depth > _TRANSFER_MAX_DEPTH or len(self.text) > _TRANSFER_MAX_CHARS:
            return None
        while self.i < len(self.text):
            if not (self._quoted() if self.quote else self._unquoted()) or self.failed:
                return None
            self.i += 1
        if self.quote:
            return None
        self._end_command('')
        return None if self.failed else self.items

    def _quoted(self) -> bool:
        ch = self.text[self.i]
        if ch == self.quote:
            self.quote = None
        elif self.quote == '"' and ch in '$`':
            found = self._substitution()
            if found is not None:
                return found
            self.word += ch
        elif self.quote == '"' and ch == '\\' and self.text[self.i + 1:self.i + 2] in ('$', '`', '"', '\\', '\n'):
            self.i += 1  # only these lose the backslash in double quotes; before anything else it stays
            self.word += '' if self.text[self.i] == '\n' else self._literal(self.text[self.i])
        else:
            self.word += self._literal(ch)
        return True

    def _literal(self, ch: str) -> str:
        """A quoted or escaped character as it goes into the word: a ~ where an unquoted one would be expanded is
        marked, as one the shell leaves."""
        return _TRANSFER_LITERAL_TILDE if ch == '~' and self._tilde_place() else ch

    def _tilde_place(self) -> bool:
        """Whether a ~ here starts a tilde prefix: at the start of the word, or of an assignment's value or a part of
        it after a :."""
        in_value = re.match(r'[A-Za-z_][A-Za-z0-9_]*\+?=', self.word) is not None
        return not self.word or (self.word[-1] in '=:' and in_value)

    def _unquoted(self) -> bool:
        text, i, ch = self.text, self.i, self.text[self.i]
        if ch in '$`<>':
            found = self._substitution()
            if found is not None:
                return found
        if ch in '\'"':
            self.quote, self.in_word = ch, True
        elif ch == '\\' and text[i + 1:i + 2] == '\n':
            self.i += 1  # a backslash-newline continues the line
        elif ch == '\\' and i + 1 < len(text):
            self.i += 1
            self.word, self.in_word = self.word + self._literal(text[self.i]), True
        elif ch == '#' and not self.in_word:
            end = text.find('\n', i)
            self.i = (len(text) if end < 0 else end) - 1  # a comment runs to the end of its line
        elif ch == '(':
            self._open()
        elif ch == ')':
            self._close()
        elif ch in '<>' or text.startswith('&>', i):
            self._redirect()
        elif ch in ';&|\n':
            self._separator(ch)
        elif ch in ' \t\r':
            self._end_word()
        elif ch == '~' and self.in_word and not self.word:
            self.word += _TRANSFER_SUBSTITUTED  # after empty quotes: bash leaves the ~, zsh expands it
        else:
            self.word, self.in_word = self.word + self._mark(ch), True
        return True

    def _mark(self, ch: str) -> str:
        """An unquoted character as it goes into the word: a { , or } bash may brace-expand is marked, unless it is part
        of a ${…} parameter."""
        if ch == '{' and (self.param or 0 <= self.dollar == len(self.word) - 1):
            self.param += 1
        elif ch == '}' and self.param:
            self.param -= 1
        elif ch == '$':
            self.dollar = len(self.word)
        elif not self.param:
            return _TRANSFER_BRACE_MARKS.get(ch, ch)
        return ch

    def _substitution(self) -> Optional[bool]:
        """Read a $( ), $(( )), backtick or <( ) substitution starting here; None when none starts here."""
        text, i, inner = self.text, self.i, None
        if text.startswith('$((', i) and _transfer_arithmetic_end(text, i + 2) > 0:
            end = _transfer_arithmetic_end(text, i + 2)
            bodies = _transfer_text_bodies(text[i + 3:end - 1])  # what its $( ) run
            if bodies is None:
                return False
            self._substitute(bodies, self._substitutions_at() if bodies else None)
        elif text.startswith('$(', i) or (not self.quote and text.startswith(('<(', '>('), i)):
            end = _transfer_paren_end(text, i + 2)
            inner = text[i + 2:end]
        elif text[i] == '`':
            end = _transfer_backtick_end(text, i + 1)
            if end < 0:
                return None  # a lone backtick, as PowerShell writes its escapes
            inner = text[i + 1:end]
        else:
            return None
        if end < 0:
            return False
        if inner is not None:
            items = _TransferLexer(inner, self.depth + 1).read()
            if items is None:
                return False
            self._flush_leading()
            self.items += [('$(', None, self.before, '', None)] + items + [(')', None, '', '', None)]
        self.word, self.in_word, self.i = self.word + _TRANSFER_SUBSTITUTED, True, end
        return True

    def _open(self) -> None:
        if self.case and self.case[-1] == 'pattern':
            return  # the optional ( before a case pattern
        if self.in_word and self.text.startswith('((', self.i) and \
                (self.word == 'for' or self.word in _TRANSFER_LEADING_WORDS):
            self._end_word()  # a reserved word ends at a (, as in for((…)) or while((…))
        head = self.argv[:-1] if self.argv[-1:] == ['for'] else self.argv
        end = _transfer_arithmetic_end(self.text, self.i + 1) if self.text.startswith('((', self.i) else -1
        if end > 0 and not self.in_word and all(w in _TRANSFER_LEADING_WORDS for w in head):
            # An arithmetic command, or a for loop's (( )) header, is one word, and runs only its substitutions; a
            # header's step runs after each pass of the body, so the walker runs that part there.
            parts = _transfer_arithmetic_parts(self.text[self.i + 2:end - 1]) if self.argv[-1:] == ['for'] else None
            bodies = _transfer_text_bodies(';'.join(parts[:2]) if parts else self.text[self.i + 2:end - 1])
            if bodies is None or (parts and _transfer_text_bodies(parts[2]) is None):
                self.failed = True
                return
            self._substitute(bodies, self._substitutions_at() if bodies else None)
            self.argv.append(self.text[self.i:end + 1])
            self.i = end
            return
        rest = self.text[self.i + 1:].lstrip(' \t')
        name = self.word if self.in_word else (self.argv[-1] if self.argv else '')
        head = self.argv if self.in_word else self.argv[:-1]
        leading = head[:-1] if head[-1:] == ['function'] else head
        if rest.startswith(')') and all(w in _TRANSFER_LEADING_WORDS for w in leading) and \
                re.match(r'^[\w.:-]+$', name):
            # `name()` or `name ()` defines a function; the body that follows runs only when it's called.
            self.argv, self.word, self.in_word = leading, '', False
            self._flush()  # a then, do or { before it still opens its compound
            self.items.append(('func', [name], self.before, '', None))
            self.i = self.text.index(')', self.i)
            return
        self._end_word()
        self._flush()
        self.items.append(('(', None, self.before, '', None))
        self.before = ''

    def _close(self) -> None:
        if self.case and self.case[-1] == 'pattern':
            # A case pattern ends at its ), and the arm's commands follow.
            self.case[-1] = 'body'
            self.word, self.in_word = '', False
            self.items.append(('arm', None, '', '', None))
            return
        self._end_command('')
        self.items.append((')', None, '', '', None))
        self.before = ';'

    def _redirect(self) -> None:
        """A redirection's operator, an fd number written against it, and its target are not arguments; it is kept as
        the fd it sets and what that fd then holds."""
        text, word = self.text, self.word
        fd = int(word) if self.in_word and word.isdigit() and text[self.i] != '&' else None
        if fd is None:
            self._end_word()
        self.word, self.in_word = '', False
        op = re.match(r'&>>?|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>', text[self.i:]).group(0)
        target, end = _transfer_read_word(text, self.i + len(op))
        fed = _TransferStdin('file')  # a heredoc or here-string feeds its text
        if op in ('<<', '<<-'):
            # An unquoted delimiter leaves the body's substitutions to run, with the command, before it does.
            quoted = any(c in text[self.i + len(op):end] for c in '\'"\\')
            self.heredocs.append((target, op == '<<-', None if quoted else self._substitutions_at(), fed))
        else:
            # A target's substitutions run with the command too, such as a here-string's "$(curl …)".
            start = self.i + len(op)
            end, bodies = _transfer_word_end(text, start)
            if end < 0:
                self.failed = True
                return
            self._substitute(bodies, self._substitutions_at() if bodies else None)
            words = _transfer_words(text[start:end]) if op == '<<<' else []
            fed.text = ' '.join(words) if words else None
        to = fd if fd is not None else 0 if op[0] == '<' else 1
        if op in ('<&', '>&') and (target.isdigit() or target == '-'):
            self.io.append((to, int(target) if target.isdigit() else 'null'))
        elif op in ('<<', '<<-', '<<<'):
            self.io.append((to, fed))
        else:
            self.io.append((to, 'null' if target == '/dev/null' else 'file'))
            if op[0] == '&' or (op == '>&' and fd is None):
                self.io.append((2, 1))  # &> and >&file send stderr there too
        self.i = end - 1

    def _separator(self, ch: str) -> None:
        text, i = self.text, self.i
        pair = text[i:i + 2]
        if self.case and self.case[-1] == 'pattern' and ch == '|':
            return  # pattern alternatives
        if self.case and self.case[-1] == 'body' and pair in (';;', ';&'):
            self._end_command(';')
            self.case[-1] = 'pattern'
            self.i += 2 if text.startswith(';;&', i) else 1
            return
        if pair == '|&':
            self.io.append((2, 1))  # |& also pipes stderr, after the command's own redirections
        if pair in ('&&', '||', '|&'):
            self._end_command('|' if pair == '|&' else pair)
            self.i += 1
        else:
            self._end_command(ch if ch in '&|' else ';')
        if ch == '\n':
            self._skip_heredocs()

    def _skip_heredocs(self) -> None:
        """A heredoc's body starts on the next line and is input, not commands, but for the substitutions in one whose
        delimiter is unquoted, which run with its command."""
        text, shift = self.text, 0
        while self.heredocs:
            delimiter, strip_tabs, at, fed = self.heredocs.pop(0)
            lines = []
            while self.i + 1 < len(text):
                end = text.find('\n', self.i + 1)
                line = text[self.i + 1:] if end < 0 else text[self.i + 1:end]
                self.i = len(text) - 1 if end < 0 else end
                line = line.lstrip('\t') if strip_tabs else line
                if line == delimiter:
                    break
                lines.append(line)
            body = '\n'.join(lines)
            bodies, fed.text = (_transfer_text_bodies(body), _transfer_expanded(body)) if at else ([], body)
            if bodies is None:
                self.failed = True
                return
            shift += self._substitute(bodies, (at[0] + shift, at[1]) if at else None)

    def _substitutions_at(self) -> tuple:
        """Where substitutions that run with the current command go: after the reserved words that lead it, so they
        run only when it does; (index in items, operator before)."""
        self._flush_leading()
        return len(self.items), self.before

    def _substitute(self, bodies: List[str], at: Optional[tuple]) -> int:
        """Insert each body as a substitution at (index in items, operator before); how many items that added."""
        added = []
        for body in bodies:
            items = _TransferLexer(body, self.depth + 1).read()
            if items is None:
                self.failed = True
                return 0
            added += [('$(', None, at[1], '', None)] + items + [(')', None, '', '', None)]
        if added:
            self.items[at[0]:at[0]] = added
        return len(added)

    def _end_word(self) -> None:
        if not self.in_word:
            return
        marked, state = self.word, self.case[-1] if self.case else None
        self.word, self.in_word, self.param, self.dollar = '', False, 0, -1
        word = marked.translate(_TRANSFER_UNMARK)
        at_start = all(w in _TRANSFER_LEADING_WORDS for w in self.argv)
        if word == '-p' and self.argv[-1:] == ['time'] and at_start:
            return  # bash's time -p sets only how the timing is printed; zsh runs -p as the command
        if state == 'head':
            self.case[-1] = 'pattern' if word == 'in' else 'head'  # `case WORD in` runs nothing
        elif state == 'pattern':
            if word == 'esac':
                self._esac()
        elif word == 'case' and at_start:
            self._flush()
            self.items.append(('case', None, self.before, '', None))
            self.case.append('head')
        elif word == 'esac' and at_start and state == 'body':
            self._esac()
        elif word == 'do' and self._loop_header():
            self._end_command(';')  # `for x do` reads as `for x; do`
            self.argv.append(word)
        elif _transfer_is_assignment(word) and all(_transfer_is_assignment(w) or w in _TRANSFER_LEADING_WORDS
                                                   for w in self.argv):
            self.argv.append(word)  # an assignment before the command is not brace-expanded
        else:
            words = [w.translate(_TRANSFER_UNMARK) for w in _transfer_braces(marked)]
            self.argv += words if len(words) == 1 else [w for w in words if w]  # an empty result is no word

    def _loop_header(self) -> bool:
        """Whether the words so far end in a for or select header with no `in` list, which a `do` may follow at once."""
        n = 0
        while n < len(self.argv) and self.argv[n] in _TRANSFER_LEADING_WORDS:
            n += 1
        core = self.argv[n:]
        return len(core) == 2 and core[0] in ('for', 'select') and core[1] != 'in'

    def _esac(self) -> None:
        self._flush()
        self.case.pop()
        self.items.append(('esac', None, '', '', None))

    def _flush_leading(self) -> None:
        """Emit the reserved words that lead the current command, so a substitution in it runs only when they let it."""
        n = 0
        while n < len(self.argv) and (self.argv[n] in _TRANSFER_LEADING_WORDS or self.argv[n] == 'function'):
            n += 2 if self.argv[n] == 'function' else 1
        if n:
            self.items.append(('cmd', self.argv[:n], self.before, '', []))
            self.argv, self.before = self.argv[n:], ''

    def _flush(self) -> None:
        """Emit the reserved words read so far ahead of the compound command they lead."""
        if self.argv:
            self.items.append(('cmd', self.argv, self.before, '', self.io))
            self.argv, self.io, self.before = [], [], ''

    def _end_command(self, after: str) -> None:
        self._end_word()
        if self.argv:
            self.items.append(('cmd', self.argv, self.before, after, self.io))
            self.ends[id(self.items[-1])] = self.i
            self.before = after
        else:
            if self.items and self.items[-1][0] in (')', 'esac') and (after or self.io):
                # A pipe, redirection or & after a subshell or case applies to the whole compound.
                kind, _, before, _, _ = self.items[-1]
                self.items[-1] = (kind, None, before, after, self.io)
            if after not in (';', ''):
                self.before = after
        self.argv, self.io = [], []


def _transfer_braces(word: str) -> List[str]:
    """A word's brace expansions, as bash makes them from its marked { , }: a {a,b} list or a {1..3} or {a..c}
    sequence, nested and in order; a brace that is neither is kept as written."""
    start = word.find('\1')
    while start >= 0:
        depth, commas, end = 0, [], -1
        for j in range(start, len(word)):
            depth += {'\1': 1, '\3': -1}.get(word[j], 0)
            if word[j] == '\2' and depth == 1:
                commas.append(j)
            if depth == 0:
                end = j
                break
        bounds = [start] + commas + [end]
        parts = [word[a + 1:b] for a, b in zip(bounds, bounds[1:])] if commas and end > 0 else \
            _transfer_sequence(word[start + 1:end]) if end > 0 else None
        if parts is not None:
            import itertools
            tails = _transfer_braces(word[end + 1:])
            return list(itertools.islice((word[:start] + part + tail for whole in parts
                                          for part in _transfer_braces(whole) for tail in tails), _TRANSFER_MAX_WORDS))
        start = word.find('\1', start + 1)
    return [word]


def _transfer_sequence(body: str) -> Optional[List[str]]:
    """The words a {x..y} or {x..y..step} sequence of integers or letters makes, as bash 5 makes them; None for any
    other brace."""
    match = re.match(r'^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$', body)
    if not match or match.group(1).isalpha() != match.group(2).isalpha():
        return None
    first, last = match.group(1), match.group(2)
    step = abs(int(match.group(3) or 1)) or 1
    a, b = (ord(first), ord(last)) if first.isalpha() else (int(first), int(last))
    values = range(a, b + (1 if b >= a else -1), step if b >= a else -step)[:_TRANSFER_MAX_WORDS]
    if first.isalpha():
        return [chr(c) for c in values]
    width = max(len(first), len(last)) if re.match(r'^-?0\d', first) or re.match(r'^-?0\d', last) else 0
    return [str(n).zfill(width) for n in values]


def _transfer_words(text: str) -> List[str]:
    """A string's words, split as the shell splits them, without its operators."""
    return [w for item in (_TransferLexer(text).read() or []) if item[0] == 'cmd' for w in item[1]]


def _transfer_env(env: Dict, key: str) -> str:
    """A variable as the command sees it: set or unset in the command, else unknown when the hook's environment has it,
    whose values never reach a host or a lookup."""
    if key in env:
        return env[key]
    if _TRANSFER_UNKNOWN_ENV in env:
        return _TRANSFER_SUBSTITUTED
    return '' if _TRANSFER_CLEAN_ENV in env or not os.environ.get(key) else _TRANSFER_SUBSTITUTED


def _transfer_is_assignment(token: str) -> bool:
    """NAME=value, or NAME+=value, which appends to the value."""
    name = token.split('=', 1)[0]
    name = name[:-1] if name.endswith('+') else name
    return '=' in token and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) is not None


def _transfer_appends(words: List[str], shell: Dict) -> List[str]:
    """The words with each leading NAME+=value made NAME=value: appended to the earlier or shell value in a command of
    only assignments, and unknown before a command, where bash 3 appends to nothing and bash 5 and zsh to that value."""
    given, words, bare = {}, list(words), all(_transfer_is_assignment(w) for w in words)
    for i, word in enumerate(words):
        if not _transfer_is_assignment(word):
            break
        name, value = word.split('=', 1)
        if name.endswith('+'):
            name = name[:-1]
            before = given[name] if name in given else _transfer_variable(shell, name)[0] or ''
            value = (before if bare else _TRANSFER_SUBSTITUTED) + value
            words[i] = name + '=' + value
        given[name] = value
    return words


def _transfer_program_name(token: str) -> str:
    """A program as it's matched: its file name in lower case, without a Windows .exe."""
    name = re.split(r'[\\/]', token)[-1].lower()
    return name[:-4] if name.endswith('.exe') else name


def _transfer_program(argv: List[str], cwd: Optional[str]) -> tuple:
    """(program, its args, inline VAR=value settings, folder it runs in, whether it runs as another user, whether a
    wrapper that is a program of its own runs it, so a builtin's name is a program too)."""
    env, argv, i, wrapper, operands, options_done, other_user = {}, list(argv), 0, None, 0, False, False
    external = False
    while i < len(argv):
        token = argv[i]
        i += 1
        if _transfer_is_assignment(token) and (wrapper is None or options_done or wrapper in ('env', 'sudo')):
            key, value = token.split('=', 1)
            env[key] = value
            continue
        if wrapper is not None and not options_done and token == '--':
            options_done = True
            continue
        if wrapper == 'env' and not options_done and token in ('-', '--ignore-environment'):
            env.clear()
            env[_TRANSFER_CLEAN_ENV] = ''
            continue
        if wrapper is not None and not options_done and token.startswith('-') and token != '-':
            if wrapper == 'command' and token in ('-v', '-V'):
                return None, [], env, cwd, other_user, external  # only looks the command up
            i, cwd = _transfer_wrapper_option(wrapper, token, argv, i, env, cwd)
            continue
        if wrapper is not None and operands > 0:
            operands -= 1
            continue
        if _transfer_program_name(token) in _TRANSFER_WRAPPERS:
            wrapper, options_done = _transfer_program_name(token), False
            operands = _TRANSFER_WRAPPERS[wrapper][2]
            other_user = other_user or wrapper in ('sudo', 'doas')
            external = external or wrapper not in ('command', 'builtin', 'exec')
            continue
        return _transfer_program_name(token), argv[i:], env, cwd, other_user, external
    return None, [], env, cwd, other_user, external


def _transfer_cd_words(args: List[str]) -> tuple:
    """A cd's option letters and its folders: options come first, -- ends them, and a lone - is a folder."""
    folders, letters = list(args), ''
    while folders and folders[0].startswith('-') and folders[0] != '-':
        option = folders.pop(0)
        if option == '--':
            break
        letters += option[1:]
    return letters, folders


def _transfer_cd(args: List[str], cwd: Optional[str], shell: Dict, given: Dict) -> tuple:
    """(the folder a cd lands in from cwd, the status it leaves): 0 where it lands, the old folder and 1 when every
    shell rejects it; None for either when that is not known, as for a folder not there now. given: its VAR=values."""
    letters, folders = _transfer_cd_words(args)
    if any(c not in 'LPeqs@0123456789' for c in letters):
        return cwd, 1  # every shell rejects the cd and stays
    if len(folders) > 1 or any(c not in 'LP' for c in letters):
        return None, None  # bash 5 rejects a second folder, bash 3 ignores it and zsh substitutes it; -e, -q, -s vary
    path = _transfer_cd_path(folders, shell, given)
    if path is None:
        return None, None
    # Bash follows the last of -L and -P, zsh any -P; -P resolves each link, so a later `cd ..` leaves the real folder.
    last = letters[max(letters.rfind('L'), letters.rfind('P'))] if letters else 'L'
    landed = {_transfer_move(cwd, path, physical) for physical in {last == 'P', 'P' in letters}}
    target = path if os.path.isabs(path) else None if cwd is None or path == '-' else os.path.join(cwd, path)
    if target is not None and os.path.exists(target) and not os.path.isdir(target):
        return cwd, 1  # a file is no folder to land in
    # The folder is read after the command ran, so one the command names elsewhere may have been made or removed by it.
    if target is None or os.path.basename(os.path.normpath(target)) in shell['names'] or len(landed) > 1:
        return None, None
    folder = landed.pop()
    return (folder, 0) if folder else (None, None)


def _transfer_tilde(word: str, shell: Dict) -> str:
    """A word with a leading ~ or ~/ made the shell's HOME, which the shell reads before a VAR=value in front of the
    command applies; marked unknown when that HOME, or the account a ~user names, is not known. A quoted ~ stays."""
    if word.startswith(_TRANSFER_LITERAL_TILDE):
        return '~' + word[1:]
    if not word.startswith('~'):
        return word
    head = word.split('/', 1)[0]
    home = _transfer_variable(shell, 'HOME')[0] if head == '~' else None
    known = home and not any(c in home for c in '$' + _TRANSFER_SUBSTITUTED)
    return (home if known else _TRANSFER_SUBSTITUTED) + word[len(head):]


def _transfer_assigned_tilde(word: str, shell: Dict) -> str:
    """A NAME=value with each ~ the shell expands in the value made a folder: the one it starts with, and any after a
    :, as for a word that starts with ~."""
    name, value = word.split('=', 1)
    return name + '=' + ':'.join(_transfer_tilde(part, shell) for part in value.split(':'))


def _transfer_cd_path(folders: List[str], shell: Dict, given: Dict) -> Optional[str]:
    """Where a cd goes as the shell expands its folder: HOME for none, with a VAR=value in front applied, and a ~ still
    there, which was quoted, a folder named ~. None when not known: a variable, substitution or glob, or a relative
    folder that CDPATH may find somewhere else first."""
    unknown = '$' + _TRANSFER_SUBSTITUTED
    if not folders:
        home = given['HOME'] if 'HOME' in given else _transfer_variable(shell, 'HOME')[0]
        return home if home and not any(c in home for c in unknown) else None
    folder = folders[0]
    cdpath = given['CDPATH'] if 'CDPATH' in given else _transfer_variable(shell, 'CDPATH')[0]
    first = folder.split('/')[0]
    searched = cdpath and folder != '-' and not folder.startswith(('/', '~')) and first not in ('.', '..')
    if searched or any(c in folder for c in unknown + '*?['):
        return None
    return './' + folder if folder.startswith('~') else folder


_TRANSFER_LOOKS = frozenset({'cd', 'pushd', 'popd', 'dirs', '[', '[[', 'test', 'ls', 'echo', 'printf', 'stat', 'cat',
                             'wc', 'head', 'tail', 'grep', 'diff', 'file', 'du', 'readlink', 'realpath', 'basename',
                             'dirname'})
_TRANSFER_MAKES_PARENTS = frozenset({'mkdir', 'install', 'git', 'unzip'})


def _transfer_names(items: List[tuple]) -> set:
    """The folders the commands in items name, as path segments: each word's last, or every one for a command that
    may make parent folders (mkdir -p); a command that only looks, such as cd, test or wc, names none."""
    names = set()
    for item in items:
        words = [w for w in item[1] if w not in _TRANSFER_KEYWORDS] if item[0] == 'cmd' else []
        program = next((_transfer_program_name(w) for w in words if not _transfer_is_assignment(w)), None)
        if program and program not in _TRANSFER_LOOKS:
            for word in words:
                segments = [segment for segment in word.split('/') if segment]
                names.update(segments if program in _TRANSFER_MAKES_PARENTS else segments[-1:])
    return names


def _transfer_move(cwd: Optional[str], path: str, physical: bool) -> Optional[str]:
    """The folder a cd to path lands in from cwd, links resolved when physical; None when cwd is not known, for `cd -`,
    or when the folder is not there now, so the cd may have failed."""
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        if cwd is None or path == '-':
            return None
        path = os.path.join(cwd, path)
    landed = os.path.realpath(path) if physical else os.path.normpath(path)
    return landed if os.path.isdir(path) and os.path.isdir(landed) else None


def _transfer_wrapper_option(wrapper: str, token: str, argv: List[str], i: int, env: Dict, cwd: Optional[str]) -> tuple:
    """Read one wrapper option, and its value when it takes one; (the next index, the folder the command runs in)."""
    short_flags, long_flags, _ = _TRANSFER_WRAPPERS[wrapper]
    name, value = token, None
    if token.startswith('--'):
        name, eq, attached = token.partition('=')
        if eq:
            value = attached
        elif name in long_flags and i < len(argv):
            value, i = argv[i], i + 1
    else:
        for j, flag in enumerate(token[1:], start=2):
            if wrapper == 'env' and flag == 'i':
                env.clear()
                env[_TRANSFER_CLEAN_ENV] = ''
            if flag in short_flags:
                name, value = '-' + flag, token[j:]
                if not value and i < len(argv):
                    value, i = argv[i], i + 1
                break
    if value is not None and name in {'env': ('-C', '--chdir'), 'sudo': ('-D', '--chdir')}.get(wrapper, ()):
        cwd = _transfer_move(cwd, value, True)  # a chdir, so links resolve
    elif value is not None and name in ('-S', '--split-string') and wrapper == 'env':
        argv[i:i] = _transfer_words(value)
    elif value is not None and name in ('-u', '--unset') and wrapper == 'env':
        env[value] = ''
    return i, cwd


def _transfer_both(a: Optional[bool], b: Optional[bool]) -> Optional[bool]:
    """Whether two conditions both hold: False when either fails, None when either is unknown."""
    if a is False or b is False:
        return False
    return None if a is None or b is None else True


def _transfer_follows(before: str, status: Optional[int]) -> bool:
    """Whether a pipeline runs after its && or ||, given the last literal true (0) or false (1)."""
    return not ((before == '&&' and status == 1) or (before == '||' and status == 0))


def _transfer_runs(shell: Dict) -> Optional[bool]:
    return shell['frames'][-1]['runs'] if shell['frames'] else shell['live']


def _transfer_snapshot(shell: Dict) -> tuple:
    return shell['cwd'], dict(shell['vars']), dict(shell['functions'])


def _transfer_restore(shell: Dict, saved: Optional[tuple], subshell: bool = False) -> None:
    """Undo the cd and variables since saved. A subshell also undoes its function definitions; one defined in a body
    that may not have run is kept, so its calls are still followed."""
    if saved:
        shell['cwd'], shell['vars'] = saved[0], dict(saved[1])
        if subshell:
            shell['functions'] = dict(saved[2])


def _transfer_changes(shell: Dict, saved: tuple) -> set:
    """What a cd, assignment, export or unset changed since saved: '' for the folder, else each variable."""
    now = shell['vars']
    names = {key for key in set(saved[1]) | set(now) if saved[1].get(key) != now.get(key)}
    return names | ({''} if shell['cwd'] != saved[0] else set())


def _transfer_forget(shell: Dict, names: set) -> None:
    """Make what may or may not have changed unknown: the folder, so no config is read from a guessed one, and each
    variable, which then reads like a substitution's output."""
    if '' in names:
        shell['cwd'] = None
    shell['vars'].update((name, (_TRANSFER_SUBSTITUTED, None)) for name in names if name)


def _transfer_variable(shell: Dict, name: str) -> tuple:
    """A shell variable as (its value or None when unset, whether it is exported); one the shell never set is the hook's
    own environment's, which is exported."""
    if name in shell['vars']:
        return shell['vars'][name]
    if _TRANSFER_UNKNOWN_ENV in shell['vars']:
        return _TRANSFER_SUBSTITUTED, None
    inherited = _TRANSFER_CLEAN_ENV not in shell['vars'] and name in os.environ
    # Only HOME and CDPATH, which place folders, are read from the hook's environment; any other value stays unknown.
    value = os.environ.get(name) if name in ('HOME', 'CDPATH') else _TRANSFER_SUBSTITUTED
    return (value if inherited else None), inherited


def _transfer_exported(shell: Dict) -> Dict:
    """The variables a command gets from the shell; one unset or not exported hides the hook's own value, and one that
    may or may not be exported (None) reads like a substitution's output."""
    return {name: _TRANSFER_SUBSTITUTED if exported is None else value if exported and value is not None else ''
            for name, (value, exported) in shell['vars'].items()}


def _transfer_doubt(pipe: Dict) -> bool:
    """Whether a pipeline runs only through an && or || after a status that is not known."""
    return pipe['prior'] is None and pipe['before'] in ('&&', '||')


def _transfer_pop(frames: List[Dict], kinds: tuple) -> Optional[Dict]:
    """Close the innermost compound command of one of these kinds."""
    while frames:
        frame = frames.pop()
        if frame['kind'] in kinds:
            return frame
    return None


def _transfer_pipeline(before: str, runs: Optional[bool], shell: Dict) -> None:
    """Start a pipeline: whether it runs, and the operator and status before it, which settle the status it leaves."""
    shell['pipe'] = {'before': before, 'prior': shell['status'], 'runs': runs, 'negate': False, 'leading': False}


def _transfer_begin(before: str, shell: Dict) -> None:
    """Start the pipeline a command or compound begins, unless it continues one after a | or a leading `!`; && and ||
    decide whether the whole pipeline runs, and any other operator also starts a list."""
    if before == '|':
        # A later command of a pipeline sees the status from before it in bash 5 but 0 in bash 3, so only 0 is known.
        shell['status'] = 0 if shell['pipe']['prior'] == 0 else None
    if before == '|' or shell['pipe']['leading']:
        return
    if before not in ('&&', '||'):
        shell['start'] = _transfer_snapshot(shell)
    _transfer_pipeline(before, _transfer_both(_transfer_runs(shell), _transfer_follows(before, shell['status'])), shell)


def _transfer_end(shell: Dict) -> None:
    """Set the status a finished pipeline leaves: the one before it when it never ran, else its last command's, flipped
    by `!`, and unknown when an unknown status let it run and skipping it would have left another."""
    pipe, status = shell['pipe'], shell['status']
    if pipe['runs'] is False:
        status = pipe['prior']
    else:
        status = {0: 1, 1: 0}.get(status) if pipe['negate'] else status
        skipped = {'&&': 1, '||': 0}.get(pipe['before'])
        if pipe['prior'] is None and skipped is not None and status != skipped:
            status = None
    shell['status'] = status


def _transfer_finish(after: str, shell: Dict) -> None:
    """End a pipeline element: the pipeline ends unless a | follows, and a backgrounded list runs in a subshell."""
    if after != '|':
        _transfer_end(shell)
    if after == '&':
        _transfer_restore(shell, shell['start'], True)
        shell['status'] = 0  # starting a background job succeeds


def _transfer_open(kind: str, runs: Optional[bool], shell: Dict, head: tuple) -> None:
    """Open a compound command, setting the pipeline and list around it aside until it closes; a function's body is
    only defined, so it never runs here. head is the item that starts it, kept for a function's calls."""
    name = shell['function'] if kind != '$(' else None
    if name is not None:
        runs, shell['function'] = False, None
    if kind != '$(':
        shell['pipe']['leading'] = False  # a substitution runs inside the command that a leading `!` still awaits
    frames = shell['frames']
    if len(frames) >= _TRANSFER_MAX_NESTING:
        raise ValueError('nested too deep')  # caught where the walk starts, so the call sends no transfer
    frames.append({'kind': kind, 'base': runs, 'runs': runs, 'rel': True, 'alive': True, 'decided': False,
                   'saved': None, 'state': _transfer_snapshot(shell), 'status': shell['status'],
                   'calls': len(shell['calls']), 'piped_in': shell.pop('opening_pipe', False),
                   'piped_out': _transfer_ends_piped(head, shell),
                   'outer': (shell['pipe'], shell['start']), 'defines': name, 'head': (shell['at'], head),
                   'iterates': None, 'repeats': False, 'forever': False, 'counter': None, 'continued': False,
                   'left': None, 'doubt': _transfer_doubt(shell['pipe']),
                   'jumped': None,
                   'unsure': set(), 'outside': _transfer_liveness(shell)})
    shell['start'] = _transfer_snapshot(shell)  # the body starts a list of its own
    _transfer_pipeline('', runs, shell)


def _transfer_status(frame: Dict, status: Optional[int]) -> Optional[int]:
    """The status a closed compound leaves: a jump's that ended it, 0 for a definition or an if or loop that ran no
    body, the one before it when it never ran, unknown when a body may have run, else its last command's."""
    kind, rel = frame['kind'], frame['rel']
    if frame['left']:
        return frame['left'][0]
    if frame['defines'] is not None:
        return 0
    if frame['base'] is False or kind == '$(':
        return frame['status']
    if kind == 'if' and rel is not True and frame['decided'] is not True:
        return 0 if rel is False and frame['decided'] is False else None
    if kind in _TRANSFER_LOOPS:
        if rel is False:
            return 0
        return status if kind == 'for' and rel else None
    if kind == 'case':
        return 0 if rel is False else None
    return status


def _transfer_settle(frame: Dict, tail: tuple, shell: Dict) -> None:
    """Close a compound: set the status it leaves, resume the pipeline and list around it, and keep a defined
    function's body, from its head item to tail, for the calls that run it."""
    shell['status'] = _transfer_status(frame, shell['status'])
    shell['pipe'], shell['start'] = frame['outer']
    if frame['defines'] is not None and shell['pipe']['runs'] is not False:
        at, head = frame['head']
        maybe = shell['pipe']['runs'] is None or _transfer_doubt(shell['pipe'])  # the definition may not have run
        shell['functions'][frame['defines']] = [head] + shell['items'][at + 1:shell['at']] + [tail], maybe


def _transfer_leave(frame: Dict, shell: Dict) -> None:
    """Leave a body that may not have run: what it changed is remembered as unknown, and the state before it returns."""
    if frame['saved']:
        frame['unsure'] |= _transfer_changes(shell, frame['saved'])
        _transfer_restore(shell, frame['saved'])
        frame['saved'] = None


def _transfer_doubtful(frame: Dict, shell: Dict) -> None:
    """At a compound's end, make unknown what may not have happened: a body that may not have run, what followed a jump
    that may have run, and all of it when an unknown status guarded the compound or it is a loop that may repeat."""
    for since in (frame['jumped'], frame['state'] if frame['doubt'] or frame['repeats'] else None):
        if since:
            frame['unsure'] |= _transfer_changes(shell, since)
    _transfer_leave(frame, shell)
    _transfer_forget(shell, frame['unsure'])


def _transfer_wrap(shell: Dict, first: int, layer: tuple) -> None:
    """Wrap each call from first on in one more level of (piped in, piped out, redirections)."""
    calls = shell['calls']
    for i in range(first, len(calls)):
        calls[i] = calls[i][:5] + (calls[i][5] + (layer,),) + calls[i][6:]


def _transfer_unsure_calls(calls: List[tuple], first: int = 0) -> None:
    """Mark each call from first on as one that may not have run, which is never looked up."""
    for i in range(first, len(calls)):
        calls[i] = calls[i][:6] + (True,)


_TRANSFER_JUMP_MARKS = ('runs', 'alive', 'left', 'jumped', 'repeats')


def _transfer_liveness(shell: Dict) -> tuple:
    """What a return, exit, break or continue may change in the open compounds and the shell, to put back."""
    return [tuple(f[key] for key in _TRANSFER_JUMP_MARKS) for f in shell['frames']], shell['live']


def _transfer_revive(outside: tuple, shell: Dict) -> None:
    """Undo what a return, exit, break or continue did beyond a compound that turned out to run in a subshell."""
    for frame, marks in zip(shell['frames'], outside[0]):
        frame.update(zip(_TRANSFER_JUMP_MARKS, marks))
    shell['live'] = outside[1]


def _transfer_soften(outside: tuple, shell: Dict) -> None:
    """Make what a return, exit, break or continue did beyond a call that may not run a maybe: what follows may run,
    and the compound it would have ended leaves an unknown status."""
    for frame, marks in zip(shell['frames'], outside[0]):
        if frame['alive'] is False and marks[1] is not False:
            frame['alive'], frame['runs'] = None, _transfer_both(marks[0], None)
            frame['jumped'] = frame['jumped'] or _transfer_snapshot(shell)
        if frame['left'] != marks[2]:
            frame['left'] = (None,)
        frame['repeats'] = marks[4]
    if shell['live'] is False and outside[1] is not False:
        shell['live'] = None


def _transfer_close(frame: Dict, layer: tuple, shell: Dict, background: bool = False) -> None:
    """Wrap a closed compound's commands in the pipes and redirections around it. Piped or backgrounded, its changes end
    with it; as a pipeline's last command, zsh keeps them and bash does not, so they are unknown."""
    _transfer_wrap(shell, frame['calls'], layer)
    if layer[0] and not (layer[1] or background or frame['kind'] in ('(', '$(')):
        _transfer_unsure(shell, frame['state'])
        _transfer_revive(frame['outside'], shell)
    elif layer[0] or layer[1] or background:
        _transfer_restore(shell, frame['state'], True)
        _transfer_revive(frame['outside'], shell)


def _transfer_unsure(shell: Dict, saved: tuple) -> None:
    """Make what changed since saved unknown, for what may or may not have happened: the folder and variables, and
    each function defined or removed, which then may or may not be there."""
    _transfer_forget(shell, _transfer_changes(shell, saved))
    for name, known in saved[2].items():
        shell['functions'].setdefault(name, (known[0], True))
    for name, known in list(shell['functions'].items()):
        if saved[2].get(name) is not known:
            shell['functions'][name] = known[0], True


def _transfer_branch(keyword: str, frame: Dict, shell: Dict) -> None:
    """Start the body a then, elif, else or do opens: run, skipped or maybe run, by the literal status before it, as
    far as the compound itself runs."""
    holds = {0: True, 1: False}.get(shell['status'])
    if keyword == 'then' and frame['kind'] == 'if':
        taken = _transfer_both(frame['rel'], holds)
        frame['decided'] = True if taken else None if taken is None and frame['decided'] is False else frame['decided']
    elif keyword in ('elif', 'else') and frame['kind'] == 'if':
        _transfer_leave(frame, shell)
        taken = {True: False, False: True}.get(frame['decided'])
    elif keyword == 'do' and frame['kind'] in _TRANSFER_LOOPS:
        if frame['kind'] in ('for', 'select'):
            holds = frame['iterates']
        elif frame['kind'] == 'until' and holds is not None:
            holds = not holds
        if frame['kind'] in ('while', 'until'):
            frame['forever'] = holds is True  # a test that is a literal holds every time
        taken = _transfer_both(frame['rel'], holds)
    else:
        return
    _transfer_take(frame, taken, shell)


def _transfer_take(frame: Dict, taken: Optional[bool], shell: Dict) -> None:
    """Set whether the body now starting runs; a body that may not run keeps the state before it to return to."""
    frame['rel'], frame['runs'] = taken, _transfer_both(_transfer_both(frame['base'], taken), frame['alive'])
    if taken is None and frame['saved'] is None:
        frame['saved'] = _transfer_snapshot(shell)
    shell['start'] = _transfer_snapshot(shell)


def _transfer_jump(program: str, args: List[str], shell: Dict) -> None:
    """Stop what a return, exit, break or continue cuts short: the rest of the function, the shell or subshell, or the
    loop body. One that may not run leaves the rest maybe running, and what that rest changes unknown."""
    frames, floor = shell['frames'], shell['floor']
    # None of them reaches past a subshell, and a break or continue does not leave the function it is in.
    bound = max([i for i, f in enumerate(frames) if f['kind'] in ('(', '$(') or f['piped_in'] or f['piped_out']],
                default=-1)
    if program in ('break', 'continue'):
        # A loop that is itself piped is its own subshell, so a break inside still reaches it.
        loops = [i for i, f in enumerate(frames) if f['kind'] in _TRANSFER_LOOPS and i >= max(bound, floor or 0)]
        if not loops:
            return
        target = loops[-min(int(args[0]) if args and args[0].isdigit() and int(args[0]) else 1, len(loops))]
    elif program == 'return':
        if floor is None:
            return  # outside a function, return only complains
        target = max(floor, bound)
    else:
        target = max(bound, 0)
    # Sure once the compound it ends is running: nothing between here and there can skip it, and an if or case it ends
    # surely took the branch it is in. It ends the whole shell only when the outermost compound surely runs as well.
    sure = not _transfer_doubt(shell['pipe']) and \
        all(f['rel'] is True and f['alive'] is True and not f['doubt'] for f in frames[target + 1:]) and \
        not any(f['kind'] in ('if', 'case') and f['rel'] is not True for f in frames[target:target + 1])
    whole = sure and shell['pipe']['runs'] is True if not frames else \
        sure and frames[0]['base'] is True and frames[0]['rel'] is True and not frames[0]['doubt']
    for frame in frames[target:]:
        frame['alive'] = _transfer_both(frame['alive'], False if sure else None)
        frame['runs'] = _transfer_both(frame['runs'], frame['alive'])
        # A sure break, return or exit ends the loops it leaves for good, while a continue runs its own loop again.
        frame['repeats'] = frame['repeats'] and not (sure and (program != 'continue' or frame is not frames[target]))
    if program == 'exit' and bound < 0:
        shell['live'] = _transfer_both(shell['live'], False if whole else None)
    if target < len(frames):
        # The compound ends with the jump's status, unknown when it may not have jumped, or may have earlier. A `!`
        # still flips a break or continue, while a return or exit leaves at once.
        status = int(shell['pipe']['negate']) if program in ('break', 'continue') else shell['status']
        frames[target]['left'] = (status if sure and not frames[target]['left'] else None,)
        if not sure and frames[target]['jumped'] is None:
            frames[target]['jumped'] = _transfer_snapshot(shell)
        if program == 'continue':
            frames[target]['continued'] = frames[target]['continued'] or (True if sure else None)


def _transfer_keyword(words: List[str], item: tuple, shell: Dict) -> List[str]:
    """Apply a command's leading reserved word to the open compound commands and its pipeline; the words after it."""
    keyword, rest, frames = words[0], words[1:], shell['frames']
    if keyword in ('{', 'if') + _TRANSFER_LOOPS:
        _transfer_open(keyword, shell['pipe']['runs'], shell, ('cmd', words, '', item[3], item[4]))
        if keyword in _TRANSFER_LOOPS:
            loop = frames[-1]
            loop['iterates'], loop['repeats'], loop['forever'], loop['counter'] = _transfer_loop(keyword, rest, shell)
            end = shell['ends'].get((shell['at'], len(item[1]) - len(words)), ('', None))[1]
            _transfer_touched(loop, _transfer_loop_commands(loop, shell, end))
        return [] if keyword in ('for', 'select') else rest  # a for loop's header runs nothing
    if keyword in ('!', 'function', 'time'):
        # `!` flips the status of the whole pipeline it leads, a compound included, and a second one flips it back;
        # `time` leads a pipeline and leaves its status.
        if keyword == 'function':
            shell['function'], rest = (rest[0] if rest else ''), rest[1:]
        elif keyword == '!':
            shell['pipe']['negate'] = not shell['pipe']['negate']
        shell['pipe']['leading'] = True
        return rest
    if keyword in ('}', 'fi', 'done'):
        frame = _transfer_pop(frames, {'}': ('{',), 'fi': ('if',), 'done': _TRANSFER_LOOPS}[keyword])
        if frame:
            _transfer_step_substitutions(frame, shell)
            endless = _transfer_endless(frame, shell)
            _transfer_doubtful(frame, shell)
            _transfer_settle(frame, ('cmd', [keyword], item[2], '', item[4]), shell)
            if endless:
                _transfer_jump('exit', [], shell)  # nothing after a loop that never ends runs
        shell['closed'] = frame
        return rest
    if frames:
        _transfer_branch(keyword, frames[-1], shell)
    _transfer_pipeline('', _transfer_runs(shell), shell)
    return rest


def _transfer_loop(keyword: str, rest: List[str], shell: Dict) -> tuple:
    """(whether a loop runs its body at least once: True, False or None; whether it may run it again; whether its test
    never fails; an arithmetic for's counter), from its header, or the positional parameters when it has no `in`."""
    if keyword == 'for' and rest[:1] and rest[0].startswith('(('):
        return _transfer_counted(rest[0])
    if keyword not in ('for', 'select'):
        return None, True, False, None
    listed = rest[2:] if rest[1:2] == ['in'] else shell['args']
    literal = keyword == 'for' and any('$' not in w and _TRANSFER_SUBSTITUTED not in w for w in listed or [])
    plain = listed is not None and len(listed) == 1 and not any(c in listed[0] for c in '$*?[\0')
    return True if literal else False if listed == [] else None, keyword != 'for' or not plain, False, None


_TRANSFER_NAME = r'([A-Za-z_][A-Za-z0-9_]*)'
_TRANSFER_NUMBER = r'(0|[1-9][0-9]*)'
_TRANSFER_TESTS = {'<': int.__lt__, '<=': int.__le__, '>': int.__gt__, '>=': int.__ge__, '==': int.__eq__,
                   '!=': int.__ne__}


def _transfer_counted(word: str) -> tuple:
    """_transfer_loop's answer for an arithmetic for: read when it starts its counter at a number, tests it against a
    number and steps it by a number; with no test it runs until something leaves it."""
    parts = [p.strip() for p in _transfer_arithmetic_parts(word[2:-2]) or []] if word.endswith('))') else []
    if len(parts) != 3:
        return None, True, False, None
    start = re.fullmatch(_TRANSFER_NAME + r'\s*=\s*' + _TRANSFER_NUMBER, parts[0])
    if parts[0] and not start:
        return None, True, False, None
    if not parts[1]:
        return True, True, True, None
    test = re.fullmatch(_TRANSFER_NAME + r'\s*(<=|>=|==|!=|<|>)\s*' + _TRANSFER_NUMBER, parts[1])
    if not (start and test and start.group(1) == test.group(1)):
        return None, True, False, None
    a, holds, b = int(start.group(2)), _TRANSFER_TESTS[test.group(2)], int(test.group(3))
    if not holds(a, b):
        return False, False, False, start.group(1)
    by = _transfer_step(parts[2], start.group(1))
    if by is None:
        return True, True, False, start.group(1)  # a step it can't read may repeat the body
    # The counter runs a, a + by, a + 2 by, ...: a != test fails only if it lands on the number, any other only if
    # the counter moves toward failing it.
    if test.group(2) == '!=':
        forever = by == 0 or (b - a) % by != 0 or (b - a) // by < 0
    elif test.group(2) == '==':
        forever = by == 0
    else:
        forever = by == 0 or (by > 0) == (test.group(2) in ('>', '>='))
    return True, holds(a + by, b), forever, start.group(1)


def _transfer_step(step: str, name: str) -> Optional[int]:
    """How much an arithmetic for's step adds to its counter: nothing, ++ or --, += or -= a number, or the counter
    plus or minus a number; None for anything else."""
    if not step:
        return 0
    match = re.fullmatch(r'(\+\+|--)?\s*' + _TRANSFER_NAME + r'\s*(\+\+|--)?', step)
    if match and match.group(2) == name and bool(match.group(1)) != bool(match.group(3)):
        return 1 if (match.group(1) or match.group(3)) == '++' else -1
    match = re.fullmatch(_TRANSFER_NAME + r'\s*([+-])=\s*' + _TRANSFER_NUMBER, step)
    if match and match.group(1) == name:
        return int(match.group(3)) * (1 if match.group(2) == '+' else -1)
    match = re.fullmatch(_TRANSFER_NAME + r'\s*=\s*' + _TRANSFER_NAME + r'\s*([+-])\s*' + _TRANSFER_NUMBER, step)
    if match and match.group(1) == match.group(2) == name:
        return int(match.group(4)) * (1 if match.group(3) == '+' else -1)
    return None


def _transfer_step_substitutions(frame: Dict, shell: Dict) -> None:
    """Run the substitutions in an arithmetic for's step where a pass of its body ends or a continue skips to: never
    after a sure break."""
    header = frame['head'][1][1][1:2] if frame['kind'] == 'for' else []
    parts = _transfer_arithmetic_parts(header[0][2:-2]) if header and header[0].startswith('((') else None
    items = []
    for body in _transfer_text_bodies(parts[2]) or [] if parts else []:
        items += [('$(', None, '', '', None)] + (_TransferLexer(body).read() or []) + [(')', None, '', '', None)]
    if items:
        ended = frame['alive'], frame['continued']
        reached = True if True in ended else False if ended == (False, False) else None
        runs, frame['runs'] = frame['runs'], _transfer_both(_transfer_both(frame['base'], frame['rel']), reached)
        shell['frames'].append(frame)  # inside the loop, as far as a pass of its body reached its end
        _transfer_items(items, shell, 0)
        shell['frames'].pop()
        frame['runs'] = runs


def _transfer_loop_commands(frame: Dict, shell: Dict, end: Optional[int]) -> Optional[List[List[str]]]:
    """The words of each command a loop runs in this shell, from its condition up to the item end, leaving out those in
    a subshell or substitution; None when its end is not known."""
    at, head = frame['head']
    if end is None:
        return None
    return [head[1][2 if head[1][0] in ('for', 'select') else 1:]] + _transfer_own_commands(shell['items'][at + 1:end])


def _transfer_own_commands(items: List[tuple]) -> List[List[str]]:
    """The words of each command in items that runs in this shell, not in a subshell or substitution."""
    depth, commands = 0, []
    for item in items:
        depth += 1 if item[0] in ('(', '$(') else -1 if item[0] == ')' else 0
        if item[0] == 'cmd' and not depth:
            commands.append(item[1])
    return commands


def _transfer_touched(frame: Dict, commands: Optional[List[List[str]]]) -> None:
    """An arithmetic for that may change its counter may run its body again, and its test may fail after all; a
    plain $name or ${name} only reads it."""
    name = frame['counter']
    if not name:
        return
    for word in (w for words in commands or [[name]] for w in words):
        at = word.find(name)
        while at >= 0:
            before, after = word[:at], word[at + len(name):]
            whole = not any(c.isascii() and (c.isalnum() or c == '_') for c in before[-1:] + after[:1])
            if whole and not (before.endswith('$') or (before.endswith('${') and after.startswith('}'))):
                frame['repeats'], frame['forever'] = True, False
                return
            at = word.find(name, at + 1)


def _transfer_leaves(commands: List[List[str]], shell: Dict, called: bool, seen: set) -> bool:
    """Whether commands could leave the loop they run in: a break, a continue past it, a return (but in a called
    function, where it only ends the call), eval or source, or a call to a function that could."""
    for words in commands:
        for k, word in enumerate(words):
            count = words[k + 1] if k + 1 < len(words) else '1'
            if word in ('break', 'eval', 'source', '.') or (word == 'return' and not called) or \
                    (word == 'continue' and not (re.fullmatch(r'[0-9]+', count) and int(count) <= 1)):
                return True
            if word in shell['functions'] and word not in seen:
                seen.add(word)
                if _transfer_leaves(_transfer_own_commands(shell['functions'][word][0]), shell, True, seen):
                    return True
    return False


def _transfer_endless(frame: Dict, shell: Dict) -> bool:
    """Whether a loop now closing never ends: its test never fails, and nothing it runs in this shell could leave
    it."""
    commands = _transfer_loop_commands(frame, shell, shell['at']) if frame['kind'] in _TRANSFER_LOOPS else None
    return bool(commands is not None and frame['forever'] and frame['base'] is not False and
                not _transfer_leaves(commands, shell, False, set()))


def _transfer_arithmetic(word: str) -> Optional[int]:
    """The status a (( N )) with a decimal number leaves: 0 for one that is not zero, 1 for zero; None otherwise. A
    leading zero is octal in bash and decimal in zsh, but zero either way."""
    inner = word[2:-2].strip() if word.startswith('((') and word.endswith('))') else ''
    return int(int(inner) == 0) if re.fullmatch(r'0+|[1-9][0-9]*', inner) else None


def _transfer_marker(item: tuple, shell: Dict) -> None:
    """Apply a subshell, substitution, function or case marker to the open compound commands."""
    kind, words, before, after, io = item
    frames, pipe = shell['frames'], shell['pipe']
    if kind in ('(', 'case'):
        _transfer_begin(before, shell)
        shell['opening_pipe'] = before == '|'
        _transfer_open(kind, shell['pipe']['runs'], shell, (kind, None, '', '', None))
        if kind == 'case':
            frames[-1]['rel'] = frames[-1]['runs'] = False  # nothing runs until an arm opens
    elif kind == '$(':
        # A substitution runs when its command does, and reads the stdin piped into that command.
        runs = pipe['runs'] if before == '|' or pipe['leading'] else \
            _transfer_both(_transfer_runs(shell), _transfer_follows(before, shell['status']))
        shell['opening_pipe'] = before == '|'
        _transfer_open(kind, runs, shell, item)
    elif kind == 'func':
        _transfer_begin(before, shell)
        shell['function'], shell['pipe']['leading'] = words[0], True
    elif kind == 'arm' and frames and frames[-1]['kind'] == 'case':
        _transfer_leave(frames[-1], shell)
        _transfer_take(frames[-1], None, shell)
    elif kind in (')', 'esac'):
        frame = _transfer_pop(frames, ('(', '$(') if kind == ')' else ('case',))
        if frame:
            # A subshell's cd, exports and functions end with it.
            if kind == ')':
                _transfer_restore(shell, frame['state'], True)
            else:
                _transfer_doubtful(frame, shell)
            _transfer_settle(frame, (kind, None, before, '', io), shell)
            if frame['kind'] == '$(':
                _transfer_close(frame, (frame['piped_in'], False, ((1, 'null'),)), shell)  # its output is captured
            else:
                _transfer_close(frame, (frame['piped_in'], after == '|', tuple(io or ())), shell, after == '&')
                _transfer_finish(after, shell)


def _transfer_builtin(program: str, args: List[str], shell: Dict) -> None:
    """Apply an export, unset or declaration, or a command made only of assignments (program ''), to the commands
    after it."""
    if program == 'unset':
        _transfer_unset(args, shell)
    elif program in _TRANSFER_DECLARES:
        _transfer_declare(program, args, shell)
    else:
        _transfer_assign(program, args, shell)


def _transfer_assign(program: str, args: List[str], shell: Dict) -> None:
    """Apply an export, or a command made only of assignments (program '')."""
    for arg in (a for a in args if not a.startswith('-')):
        name, eq, value = arg.partition('=')
        if name.endswith('+'):
            _transfer_forget(shell, {name[:-1]} - {''})  # bash appends, and zsh rejects it
        elif program == 'export':
            shell['vars'][name] = (value if eq else _transfer_variable(shell, name)[0], '-n' not in args)
        else:
            shell['vars'][name] = (value, _transfer_variable(shell, name)[1])  # an exported one stays exported


def _transfer_unset(args: List[str], shell: Dict) -> None:
    """unset -f removes functions, and -v or a bare name variables with their export. A bare name with no variable set
    removes the function in bash but not zsh, so it may or may not remain, as after an unset -f that may not run."""
    sure = shell['pipe']['runs'] is True and not _transfer_doubt(shell['pipe'])
    for name in (a for a in args if not a.startswith('-')):
        value = _transfer_variable(shell, name)[0]
        known = shell['functions'].get(name)
        exported = _transfer_variable(shell, name)[1]
        if '-f' not in args and exported in _TRANSFER_LENT:
            shell['vars'][name] = (_TRANSFER_SUBSTITUTED if exported == _TRANSFER_LENT[1] else None, exported)
        elif '-f' not in args:
            shell['vars'][name] = (None, False)
        if known and ('-f' in args or ('-v' not in args and (value is None or _TRANSFER_SUBSTITUTED in value))):
            if sure and '-f' in args:
                del shell['functions'][name]
            else:
                shell['functions'][name] = known[0], True


def _transfer_declare(program: str, args: List[str], shell: Dict) -> None:
    """declare or typeset outside a function set NAME=value, exporting with -x and not with +x. Other options, +=,
    local, readonly, and declarations in a function leave the names unknown; a local one put back after its call."""
    on = off = ''
    while args and args[0][:1] in '-+' and len(args[0]) > 1:
        option, args = args[0], args[1:]
        if option == '--':
            break
        on, off = (on + option[1:], off) if option[0] == '-' else (on, off + option[1:])
    plain = program in ('declare', 'typeset') and shell['floor'] is None and set(on + off) <= {'x'} and not (on and off)
    sure = shell['pipe']['runs'] is True and not _transfer_doubt(shell['pipe'])
    for name, eq, value in (arg.partition('=') for arg in args):
        lent = _transfer_variable(shell, name.rstrip('+'))[1]
        # Both shells export a local -x NAME=value to the call's commands; other local values they pass on differently.
        exported_local = program == 'local' and 'x' in on and not off and eq and not name.endswith('+')
        if lent in _TRANSFER_LENT and program != 'readonly' and 'g' not in on + off:
            shell['vars'][name.rstrip('+')] = (value if exported_local else _TRANSFER_SUBSTITUTED, lent)  # call-local
            continue
        if exported_local:
            shell['vars'][name] = (value, True)
        elif not plain or name.endswith('+'):
            _transfer_forget(shell, {name.rstrip('+')} - {''})
        if not plain or name.endswith('+'):
            # Local to the call in both shells, unless zsh makes it global: declare or typeset -x.
            scoped = program == 'local' or (program != 'readonly' and not {'g', 'x'} & set(on + off))
            if shell['scoped'] and sure and scoped:
                shell['scoped'][-1].add(name.rstrip('+'))
            continue
        current, exported = _transfer_variable(shell, name)
        shell['vars'][name] = (value if eq else current, True if on else False if off else exported)


def _transfer_stdin_script(program: str, args: List[str]) -> Optional[List[str]]:
    """The positional parameters of a shell that reads its script from stdin, with no -c string and no script file;
    None for any other command."""
    if program not in _TRANSFER_SHELLS:
        return None
    i = 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg in ('-o', '+o', '-O', '+O', '--rcfile', '--init-file'):
            i += 1
        elif arg == '-':
            return args[i:]
        elif arg == '--':
            return None if i < len(args) else []
        elif len(arg) > 1 and arg[0] in '-+' and arg[1] != '-' and ('c' in arg or 's' in arg):
            return None if 'c' in arg else args[i:]
        elif not (len(arg) > 1 and arg[0] in '-+'):
            return None  # a script file
    return []


def _transfer_script_stdin(lexer, items: List[tuple]) -> List[tuple]:
    """A script read from stdin: each command's stdin is the script's lines after the one it ends on, which a command
    that reads stdin, such as curl -K - or nc, takes for its input."""
    out = []
    for item in items:
        end = lexer.ends.get(id(item))
        line_end = lexer.text.find('\n', end) if end is not None else -1
        rest = lexer.text[line_end + 1:] if line_end >= 0 else ''
        if rest.strip():
            fed = _TransferStdin('file')
            fed.text = rest
            item = item[:4] + (((0, fed),) + tuple(item[4]),)
        out.append(item)
    return out


def _transfer_stdin_text(layers: tuple) -> Optional[str]:
    """The heredoc or here-string text a call's stdin reads, as its pipes and redirections set it; None otherwise."""
    fed = None
    for piped_in, _, redirections in reversed(layers):
        fed = None if piped_in else fed
        for fd, value in redirections:
            fed = (value if isinstance(value, _TransferStdin) else None) if fd == 0 else fed
    return fed.text if fed is not None else None


def _transfer_stdin_args(tool: str, args: List[str], text: Optional[str]) -> List[str]:
    """curl's or wget's arguments, with a config (curl -K -) or a URL list (wget -i -) read from stdin put in place."""
    names = ('-K', '--config') if tool == 'curl' else ('-i', '--input-file')
    out, i = [], 0
    while i < len(args):
        arg, i = args[i], i + 1
        joined = arg in (names[0] + '-', names[1] + '=-')
        if text is None or not (joined or (arg in names and args[i:i + 1] == ['-'])):
            out.append(arg)
            continue
        i += 0 if joined else 1
        out += _transfer_curl_config(text) if tool == 'curl' else [line.strip() for line in text.splitlines()
                                                                    if line.strip()]
    return out


def _transfer_curl_config(text: str) -> List[str]:
    """A curl config's options as arguments: one per line, with or without its dashes, its value after blanks, = or :,
    quoted or not; # starts a comment."""
    args = []
    for line in (line.strip() for line in text.splitlines()):
        match = re.match(r'(-{0,2}[A-Za-z0-9][A-Za-z0-9-]*)(?:\s*[=:]\s*|\s+|$)(.*)$', line)
        if not match or line.startswith('#'):
            continue
        name, value = match.group(1), match.group(2).strip()
        args.append(name if name.startswith('-') else '--' + name)
        if value:
            args.append(value[1:-1] if len(value) > 1 and value[0] == value[-1] == '"' else value)
    return args


def _transfer_shell_string(program: str, args: List[str]) -> Optional[str]:
    """The command string `sh -c` or `powershell -Command` runs; None for any other command."""
    if program in _TRANSFER_SHELLS:
        has_c, i = False, 0
        while i < len(args):
            arg, i = args[i], i + 1
            if arg in ('-o', '+o', '-O', '+O'):
                i += 1
            elif arg[:1] in '-+' and not arg.startswith('--') and len(arg) > 1:
                has_c = has_c or 'c' in arg
            elif not arg.startswith('--'):
                return arg if has_c else None
    if program in _TRANSFER_POWERSHELLS:
        for i, arg in enumerate(args):
            name = arg[1:].lower() if arg[:1] in '-/' else ''
            if name == 'c' or (len(name) >= 3 and 'command'.startswith(name)):
                return _transfer_hashtables_emptied(' '.join(args[i + 1:]))
    return None


def _transfer_hashtables_emptied(text: str) -> str:
    """A PowerShell command with each @{ } hashtable made empty: a ; in one separates its entries, not commands, and
    what it holds names no host the cmdlet reaches."""
    out, i, quote = [], 0, None
    while i < len(text):
        if not quote and text.startswith('@{', i):
            out.append('@{}')
            i = _transfer_hashtable_end(text, i + 2)
            continue
        ch = text[i]
        quote = (None if ch == quote else quote) if quote else (ch if ch in '\'"' else None)
        out.append(ch)
        i += 1
    return ''.join(out)


def _transfer_hashtable_end(text: str, i: int) -> int:
    """The index after the } that closes a PowerShell @{ whose contents start at i, past quotes and nested braces."""
    depth, quote = 1, None
    while i < len(text) and depth:
        ch = text[i]
        if quote:
            quote = None if ch == quote else quote
        elif ch in '\'"':
            quote = ch
        else:
            depth += 1 if ch == '{' else -1 if ch == '}' else 0
        i += 1
    return i


def _transfer_call(known: tuple, layer: tuple, subshell: Optional[bool], shell: Dict, depth: int) -> None:
    """Run a function's body (known: body, whether it may not exist) where called, in a subshell when piped or
    backgrounded; one that may not run, or a pipeline's last command (subshell None), leaves its changes unknown."""
    body, maybe = known
    if depth >= _TRANSFER_MAX_DEPTH or shell['calls_left'] <= 0:
        shell['status'] = None
        return
    shell['calls_left'] -= 1
    first, state = len(shell['calls']), _transfer_snapshot(shell)
    outer, outside = (shell['pipe'], shell['start'], shell['floor']), _transfer_liveness(shell)
    shell['floor'] = len(shell['frames'])
    shell['scoped'].append(set())
    _transfer_items(body, shell, depth + 1)
    for name in shell['scoped'].pop():  # a local ends with the call, and the value from before it is back
        if name in state[1]:
            shell['vars'][name] = state[1][name]
        else:
            shell['vars'].pop(name, None)
    shell['pipe'], shell['start'], shell['floor'] = outer
    _transfer_wrap(shell, first, layer)
    if maybe:
        _transfer_unsure_calls(shell['calls'], first)
    if subshell:
        _transfer_restore(shell, state, True)
        _transfer_revive(outside, shell)
    elif subshell is None or maybe or _transfer_doubt(shell['pipe']):
        _transfer_unsure(shell, state)
        _transfer_soften(outside, shell)


# The export flags of a function call's VAR=value, kept by an assignment, unset or local declaration in the body: the
# second when the name had a value before the call, which an unset in the body brings back in bash but not in zsh.
_TRANSFER_LENT = ('lent', 'lent over a value')


_TRANSFER_READERS = ('read', 'mapfile', 'readarray', 'getopts', 'printf')


def _transfer_read_names(program: str, args: List[str]) -> set:
    """The variables a read, mapfile, getopts or printf -v may set, which hold what it read and so are unknown. Every
    word that could name one is taken, which at worst leaves an extra name unknown."""
    if program == 'printf':
        named = {a[2:] or (args[i + 1] if i + 1 < len(args) else '') for i, a in enumerate(args) if a.startswith('-v')}
        return named - {''}  # an empty name would stand for the folder
    if program == 'getopts':
        return set(args[1:2]) | {'OPTARG', 'OPTIND'}
    names = {a.split('?', 1)[0] for a in args}  # zsh's read NAME?prompt
    return {n for n in names if _transfer_is_assignment(n + '=')} | {'REPLY' if program == 'read' else 'MAPFILE'}


def _transfer_lend(shell: Dict, assignments: List[str]) -> Dict:
    """Set a function call's leading VAR=value words for its body, exported, as bash and zsh do; each name's entry
    from before the call, None when it had none."""
    before, flags = {}, {}
    for word in assignments:
        name, value = word.split('=', 1)
        if name not in before:
            before[name] = shell['vars'].get(name)
            flags[name] = _TRANSFER_LENT[1 if _transfer_variable(shell, name)[0] is not None else 0]
        shell['vars'][name] = (value, flags[name])
    return before


def _transfer_take_back(shell: Dict, before: Dict) -> None:
    """Put each lent name back as it was before the call, as bash and zsh do after the body assigns, unsets or
    declares it locally. One the body exported or left unknown is unknown: bash keeps an exported value, zsh doesn't."""
    for name, entry in before.items():
        if shell['vars'].get(name, (None, None))[1] not in _TRANSFER_LENT:
            shell['vars'][name] = (_TRANSFER_SUBSTITUTED, None)
        elif entry is None:
            shell['vars'].pop(name, None)
        else:
            shell['vars'][name] = entry


def _transfer_simple(words: List[str], before: str, after: str, io: list, shell: Dict, depth: int) -> List[tuple]:
    """The calls one simple command makes, after applying its cd, export, unset or declaration; a defined function runs
    its body with the command's words as its positional parameters."""
    layer = (before == '|', after == '|', tuple(io))
    lead = next((i for i, w in enumerate(words) if not _transfer_is_assignment(w)), len(words))
    words = [_transfer_assigned_tilde(w, shell) for w in words[:lead]] + words[lead:]
    substituted, words = any(_TRANSFER_SUBSTITUTED in w for w in words), _transfer_appends(words, shell)
    name = next((w for w in words if not _transfer_is_assignment(w)), None)
    # A piped or backgrounded command runs in a subshell; the last command of a pipeline (None) does in bash, but runs
    # in this shell in zsh.
    subshell = True if after in ('|', '&') else None if before == '|' else False
    known = shell['functions'].get(name)
    if known:
        outer, shell['args'] = shell['args'], words[words.index(name) + 1:]
        lent = _transfer_lend(shell, words[:words.index(name)])
        _transfer_call(known, layer, subshell, shell, depth)  # looked up first: the body may remove the function
        _transfer_take_back(shell, lent)
        shell['args'] = outer
        if not known[1]:
            return []
        # A function that may not have been defined may leave the name to the program.
    program, args, given, cwd, other_user, external = _transfer_program(words, shell['cwd'])
    # After a wrapper that is a program of its own, a builtin's name is a program too, and changes nothing here.
    builtin = None if external else program
    declares = program in ('export',) + _TRANSFER_DECLARES
    args = [_transfer_assigned_tilde(a, shell) if declares and _transfer_is_assignment(a) else _transfer_tilde(a, shell)
            for a in args]
    env = given if _TRANSFER_CLEAN_ENV in given else {**_transfer_exported(shell), **given}
    # A command of nothing but assignments sets them in the shell, and succeeds unless a substitution in it fails.
    assigns = program is None and all(_transfer_is_assignment(w) for w in words)
    status = shell['status']
    shell['status'] = 0 if program == 'true' or builtin in (':', 'break', 'continue') else 1 if program == 'false' else \
        _transfer_arithmetic(words[0]) if len(words) == 1 else None
    if assigns and not substituted:
        shell['status'] = 0
    moved = _transfer_cd(args, cwd, shell, given) if builtin == 'cd' else None
    if builtin in ('pushd', 'popd'):
        # pushd DIR lands as cd DIR does; popd and any other pushd move by a folder stack this does not keep.
        folders = args[1:] if args[:1] == ['--'] else args
        sure = program == 'pushd' and len(folders) == 1 and folders[0][:1] not in ('+', '-')
        moved = _transfer_cd(folders, cwd, shell, given) if sure else (None, None)
    if moved:
        shell['status'] = moved[1]
    if builtin in ('set', 'shift'):
        shell['args'] = None  # the positional parameters may have changed
    if builtin in ('return', 'exit'):
        # Either leaves the status it is given, or else the one before it; a return outside a function fails.
        shell['status'] = status if not args else int(int(args[0]) % 256 > 0) if args[0].isdigit() else None
        if program == 'return' and shell['floor'] is None:
            shell['status'] = 1
    if builtin in ('return', 'exit', 'break', 'continue'):
        _transfer_jump_from(program, args, subshell, shell)
    if builtin in _TRANSFER_READERS and ((before != '|' and after != '|') or subshell is None):
        _transfer_forget(shell, _transfer_read_names(program, args))
    if builtin in ('eval', 'source', '.') and ((before != '|' and after != '|') or subshell is None):
        # Their text may set any variable or change folder, so every one, inherited ones included, becomes unknown.
        _transfer_forget(shell, {name for name in shell['vars'] if not name.startswith('\0')} | {''})
        shell['vars'][_TRANSFER_UNKNOWN_ENV] = (None, None)
        # It may also redefine any function, so each one known may no longer run as written.
        shell['functions'] = {name: (known[0], True) for name, known in shell['functions'].items()}
    if builtin in ('cd', 'pushd', 'popd', 'export', 'unset') + _TRANSFER_DECLARES or assigns:
        # A pipeline's commands run in subshells, so their cd and variables end with them, but for the last in zsh.
        if ((before != '|' and after != '|') or subshell is None) and _transfer_execs(words) is False:
            saved = _transfer_snapshot(shell)
            if moved:
                shell['cwd'] = moved[0]
            else:
                _transfer_builtin(program or '', words if assigns else args, shell)
            if subshell is None:
                _transfer_unsure(shell, saved)
            elif _transfer_doubt(shell['pipe']):
                _transfer_forget(shell, _transfer_changes(shell, saved))  # it may not have run
        _transfer_replace(words, subshell, shell)
        return []  # a builtin run through exec does not run: bash finds no such program, and zsh exits after it
    inner = _transfer_shell_string(program, args) if program else None
    # Its words after the string are $0 and then the positional parameters; a shell may read its script from stdin.
    positional = args[args.index(inner) + 2:] if inner is not None and program in _TRANSFER_SHELLS else []
    script = _transfer_stdin_script(program, args) if program and inner is None else None
    if script is not None:
        # The shell has already read the script from its stdin, so the script's commands find nothing more there.
        inner, positional = _transfer_stdin_text((layer,)), script
        layer = layer[:2] + (tuple((fd, 'null' if fd == 0 else value) for fd, value in layer[2]),)
    if inner is not None:
        # The string's commands run as the wrapper's user and read its stdin and write its stdout.
        lexer = _TransferLexer(inner, depth + 1)
        items = _transfer_script_stdin(lexer, lexer.read() or []) if script is not None else lexer.read() or []
        calls = _transfer_walk(items, cwd, env, depth + 1, positional)
        calls = [call[:4] + (call[4] or other_user, call[5] + (layer,)) + call[6:] for call in calls]
    else:
        calls = [(program, args, env, cwd, other_user, (layer,), False)] if program else []
    if program:
        _transfer_replace(words, subshell, shell)
    return calls


def _transfer_replace(words: List[str], subshell: Optional[bool], shell: Dict) -> None:
    """After a command run through exec, which replaces the shell, nothing runs; only maybe for one behind command."""
    replaced = _transfer_execs(words)
    if replaced is not False:
        _transfer_jump_from('exit', [], subshell if replaced or subshell is True else None, shell)


def _transfer_execs(words: List[str]) -> Optional[bool]:
    """Whether a command runs through exec: True for exec, or exec behind time or builtin; None behind command, which
    bash runs as the builtin and zsh looks up as a program; False otherwise."""
    rest, behind_command = [w for w in words if not _transfer_is_assignment(w)], False
    while rest and rest[0] in ('command', 'builtin', 'time', '-p', '--'):
        behind_command, rest = behind_command or rest[0] == 'command', rest[1:]
    return (None if behind_command else True) if len(rest) > 1 and rest[0] == 'exec' else False


def _transfer_jump_from(program: str, args: List[str], subshell: Optional[bool], shell: Dict) -> None:
    """A return, exit, break or continue where it runs: nothing beyond a subshell, and only maybe from the last
    command of a pipeline (subshell None), which ends its subshell in bash but runs in this shell in zsh."""
    if subshell is True:
        return
    outside = _transfer_liveness(shell)
    _transfer_jump(program, args, shell)
    if subshell is None:
        _transfer_soften(outside, shell)


def _transfer_command(item: tuple, shell: Dict, depth: int) -> List[tuple]:
    """The calls one simple command makes, if it runs or may run, after the reserved words that lead it."""
    _, words, before, after, io = item
    if words[0] not in ('}', 'fi', 'done'):
        _transfer_begin(before, shell)
    shell['opening_pipe'] = before == '|'
    while words and words[0] in _TRANSFER_KEYWORDS:
        # A body's first command is reached by its compound's pipe, which its own redirections then override.
        before = before if words[0] in ('!', 'function', 'time') else ''
        words = _transfer_keyword(words, item, shell)
    shell.pop('opening_pipe', None)
    closed = shell.pop('closed', None)
    if closed:
        _transfer_close(closed, (closed['piped_in'], after == '|', tuple(io)), shell, after == '&')
    calls = []
    if words:
        shell['pipe']['leading'] = False
        if shell['pipe']['runs'] is not False:
            # Under a condition, or an && or || after a status, that is not known, it may not have run.
            sure = shell['pipe']['runs'] is True and not _transfer_doubt(shell['pipe']) and \
                not any(frame['doubt'] for frame in shell['frames'])
            first = len(shell['calls'])
            calls = _transfer_simple(words, before, after, io, shell, depth)
            if not sure:
                _transfer_unsure_calls(calls)
                _transfer_unsure_calls(shell['calls'], first)  # and what a function it called ran
    if words or closed:
        _transfer_finish(after, shell)
    return calls


def _transfer_items(items: List[tuple], shell: Dict, depth: int) -> None:
    """Walk items in this shell, adding each call that runs or may run to its calls."""
    outer = shell['items'], shell['at'], shell['ends']
    shell['items'], shell['ends'] = items, _transfer_ends(items)
    for at, item in enumerate(items):
        shell['at'] = at
        if item[0] == 'cmd':
            shell['calls'] += _transfer_command(item, shell, depth)
        else:
            _transfer_marker(item, shell)
    shell['items'], shell['at'], shell['ends'] = outer


def _transfer_ends(items: List[tuple]) -> Dict:
    """Where each compound in items ends, (operator after it, item), by where it opens (item, word): one piped or
    backgrounded at its end is a subshell, which no jump inside it leaves."""
    ends, opened = {}, []
    for at, (kind, words, _, after, _) in enumerate(items):
        if kind in ('(', '$(', 'case'):
            opened.append((at, 0))
        elif kind in (')', 'esac') and opened:
            ends[opened.pop()] = after, at
        k = 0
        while kind == 'cmd' and k < len(words) and words[k] in _TRANSFER_KEYWORDS:
            if words[k] in ('}', 'fi', 'done') and opened:
                ends[opened.pop()] = (after if k == len(words) - 1 else ''), at
            elif words[k] in ('{', 'if') + _TRANSFER_LOOPS:
                opened.append((at, k))
                if words[k] in ('for', 'select'):
                    break  # the rest is its header
            k += 2 if words[k] == 'function' else 1
    return ends


def _transfer_ends_piped(head: tuple, shell: Dict) -> bool:
    """Whether the compound opening at head, in the item being read, is piped or backgrounded at its end."""
    item = shell['items'][shell['at']] if shell['at'] < len(shell['items']) else head
    k = len(item[1]) - len(head[1]) if head[0] == 'cmd' and item[0] == 'cmd' else 0
    return shell['ends'].get((shell['at'], k), ('', None))[0] in ('|', '&')


def _transfer_walk(items: List[tuple], cwd: Optional[str], exported: Dict, depth: int,
                   positional: List[str] = ()) -> List[tuple]:
    """Each simple command that runs or may run, as (program, args, env, folder, as another user, its (piped in, piped
    out, redirections) layers from its own outward, whether it may not have run); skipped branches and uncalled
    function bodies are left out."""
    return _transfer_shell(items, cwd, exported, depth, positional)['calls']


def _transfer_next_cwd(command: Optional[str], cwd: Optional[str]) -> Optional[str]:
    """The folder a persistent shell is in after a command, where the next command's lookups start: moved only by a cd
    that surely ran, and None when that is not known. Never raises."""
    try:
        if not isinstance(command, str) or not command.strip():
            return cwd
        items = _TransferLexer(command).read()
        return _transfer_shell(items, cwd, {}, 0)['cwd'] if items is not None else None
    except Exception:
        return None


def _transfer_shell(items: List[tuple], cwd: Optional[str], exported: Dict, depth: int,
                    positional: List[str] = ()) -> Dict:
    """The shell after walking items: the calls made, and the folder, variables and functions it ends with. A fresh
    shell has no positional parameters, and one a string runs gets the words after it."""
    variables = {name: (value, True) for name, value in exported.items()}
    shell = {'cwd': cwd, 'vars': variables, 'status': None, 'frames': [], 'function': None,
             'start': (cwd, dict(variables), {}), 'calls': [], 'functions': {}, 'calls_left': _TRANSFER_MAX_CALLS,
             'items': items, 'at': 0, 'live': True, 'floor': None, 'args': list(positional), 'ends': {},
             'names': _transfer_names(items), 'scoped': []}
    _transfer_pipeline('', True, shell)
    _transfer_items(items, shell, depth)
    return shell


def _transfer_short_option(arg: str, args: List[str], i: int, value_flags: frozenset, seen: set) -> tuple:
    """(the option in a cluster such as -sSLo that takes a value, its value, the next index); switches go to seen."""
    for j, flag in enumerate(arg[1:], start=2):
        if flag in value_flags:
            value = arg[j:]
            if not value and i < len(args):
                value, i = args[i], i + 1
            return '-' + flag, value, i
        seen.add('-' + flag)
    return arg, None, i


def _transfer_url_split(url: str):
    """A URL split as the tools read it: a scheme only at its start, and http when it has none."""
    from urllib.parse import urlsplit
    text = url.strip()
    return urlsplit(text if re.match(r'[A-Za-z][A-Za-z0-9+.-]*://', text) else 'http://' + text)


def _transfer_url_host(url: str, schemes: frozenset) -> str:
    """The host a URL names, with any login, port and path dropped; empty when it names none, or when the tool does
    not speak its scheme."""
    try:
        parts = _transfer_url_split(url)
        if parts.scheme.lower() not in schemes:
            return ''
        host = parts.hostname or ''
        if '[' in parts.netloc and not _transfer_ip(host):
            return ''  # brackets hold nothing but an IPv6 address, which older Pythons do not check
        if '%' in host and '[' not in parts.netloc:
            from urllib.parse import unquote
            host = unquote(host, errors='strict').lower()  # curl decodes a host name, then rejects what no name holds
            if any(c.isspace() or (c.isascii() and not (c.isalnum() or c in '-._')) for c in host):
                return ''
        if host.isascii():
            return host
        import unicodedata
        # curl (libidn2) and the URL standard dial each non-ASCII label in punycode, keeping ß and a final sigma.
        return '.'.join(label if label.isascii() else 'xn--' + label.encode('punycode').decode('ascii')
                        for label in unicodedata.normalize('NFC', host).split('.'))
    except ValueError:
        return ''


def _transfer_proxy_setting(env: Dict, name: str) -> Optional[str]:
    """A proxy or no_proxy variable as the tool sees it, None when unset: set or unset in the command, else inherited
    from the agent's environment. It only decides whether a host is looked up here, and is never sent."""
    if name in env:
        return env[name]
    if _TRANSFER_UNKNOWN_ENV in env:
        return _TRANSFER_SUBSTITUTED
    return None if _TRANSFER_CLEAN_ENV in env else os.environ.get(name)


def _transfer_proxied(env: Dict) -> bool:
    """Whether curl, wget, HTTPie or PowerShell finds a proxy in its environment, the command's or the agent's."""
    return any(_transfer_proxy_setting(env, key) for key in _TRANSFER_PROXY_ENV)


def _transfer_proxy_kind(value: str, default: str = 'http') -> str:
    """The kind of proxy a curl proxy string names: its scheme, or default when it has none; empty for none."""
    value = value.strip()
    if not value:
        return ''
    kind = value.split('://', 1)[0].lower() if '://' in value else default
    return 'http' if kind == 'https' else kind


def _transfer_curl_remote(url: str, kind: Optional[str], noproxy: Optional[str], env: Dict) -> bool:
    """Whether a curl URL's name goes to a proxy that resolves it: an HTTP proxy, which sends CONNECT with the name, or
    SOCKS4A or SOCKS5 with the hostname. SOCKS4 and SOCKS5 resolve here, and an empty -x, or a --noproxy entry (else
    a no_proxy or NO_PROXY one), turns the proxy off. kind is the request's own, or None for a proxy in curl's
    environment, which the command sets or the agent's shell passes on."""
    parts = _transfer_url_split(url)
    scheme = parts.scheme.lower()
    if kind is None:
        names = [scheme + '_proxy'] + ([scheme.upper() + '_PROXY'] if scheme != 'http' else []) + ['all_proxy',
                                                                                                    'ALL_PROXY']
        settings = (_transfer_proxy_setting(env, name) for name in names)
        kind = _transfer_proxy_kind(next((value for value in settings if value is not None), ''))
    host = (parts.hostname or '').lower().rstrip('.')
    if noproxy is None:
        settings = (_transfer_proxy_setting(env, name) for name in ('no_proxy', 'NO_PROXY'))
        noproxy = next((value for value in settings if value is not None), '')
    # As curl reads the list: * alone bypasses every host, else entries split on commas and blanks, their dots aside.
    entries = [entry.strip('.').lower() for entry in re.split(r'[,\s]+', noproxy)]
    if not kind or noproxy == '*' or any(entry and (host == entry or host.endswith('.' + entry)) for entry in entries):
        return False
    return kind not in ('socks4', 'socks5')


def _transfer_curl(args: List[str], env: Optional[Dict] = None) -> List[tuple]:
    """curl's URLs: sent to when their request uploads or sends data, else fetched from. Each --next starts a request,
    --resolve pins carry on, and globs reach every host unless --globoff; a rejected glob stops curl. Each carries
    whether a proxy, by option or one in its environment, resolves its name; such a proxy is handed the
    --connect-to target, and no --resolve pin applies."""
    endpoints, pins, i = [], [], 0
    while True:
        urls, sends, overrides, globoff, i, (kind, noproxy), scheme = _transfer_curl_request(args, i)
        pins += [value for option, value in overrides if option == '--resolve']
        connects = [value for option, value in overrides if option == '--connect-to']
        for url in urls:
            # A URL with no scheme takes --proto-default's, and so that scheme's port.
            url = scheme + '://' + url.strip() if scheme and not re.match(r'\s*[A-Za-z][A-Za-z0-9+.-]*://', url) else url
            expanded = [url] if globoff else _transfer_curl_glob(url)
            if expanded is None:
                return endpoints
            for one in expanded:
                remote = _transfer_curl_remote(one, kind, noproxy, env or {})
                endpoints.append(('out' if sends else 'in', _transfer_url_host(one, _TRANSFER_CURL_SCHEMES), None,
                                  _transfer_curl_dial(one, connects, [] if remote else pins), remote))
        if i >= len(args):
            return endpoints


def _transfer_curl_glob(url: str) -> Optional[List[str]]:
    """The URLs curl makes of one by expanding its {a,b} sets and [1-3] or [a-c] ranges, as far as they change the
    host; None for a glob curl rejects."""
    pieces = _transfer_glob_pieces(url)
    if pieces is None:
        return None
    urls = ['']
    for text, values in pieces:
        urls = [u + text for u in urls]
        # Past the host a glob only changes the path, so one of its values stands for all.
        in_host = not all(re.search(r'[/?#]', u.split('://', 1)[-1]) for u in urls)
        urls = [u + v for u in urls for v in (values if in_host else values[:1])][:_TRANSFER_MAX_WORDS]
    return urls


def _transfer_glob_pieces(url: str) -> Optional[List[tuple]]:
    """A curl URL as (literal text, the values of the glob after it) pieces, read as curl reads {a,b} sets, [1-3] or
    [a-c] ranges with an optional :step, a bracketed IPv6 address and backslash escapes; None for a glob it rejects."""
    pieces, text, i = [], '', 0
    while i < len(url):
        ch = url[i]
        if ch == '\\' and url[i + 1:i + 2] in ('{', '}', '[', ']', ','):
            text, i = text + url[i + 1], i + 2
            continue
        if ch in '}]':
            return None  # a close with no open
        if ch not in '{[':
            text, i = text + ch, i + 1
            continue
        end = i + 1
        while end < len(url) and url[end] != {'{': '}', '[': ']'}[ch]:
            if url[end] == ch:
                return None  # a nested open
            end += 2 if url[end] == '\\' else 1
        if end >= len(url):
            return None
        body = url[i + 1:end]
        if ch == '[' and ':' in body and _transfer_ip(body):
            text += url[i:end + 1]  # an IPv6 address, not a range
        else:
            values = [re.sub(r'\\(.)', r'\1', v) for v in re.split(r'(?<!\\),', body)] if ch == '{' else \
                _transfer_range(body)
            if values is None:
                return None
            pieces.append((text, values))
            text = ''
        i = end + 1
    return pieces + [(text, [''])]


def _transfer_range(body: str) -> Optional[List[str]]:
    """The values a curl [1-3], [01-10:2] or [a-c] range takes; None for one curl rejects."""
    match = re.match(r'^(?:(\d+)-(\d+)|([a-z])-([a-z])|([A-Z])-([A-Z]))(?::(\d+))?$', body)
    step = int(match.group(7) or 1) if match else 0
    if not step:
        return None
    if match.group(1) is not None:
        first, last = match.group(1), match.group(2)
        width = len(first) if first.startswith('0') else 0
        values = [str(n).zfill(width) for n in range(int(first), int(last) + 1, step)[:_TRANSFER_MAX_WORDS]]
    else:
        first, last = match.group(3) or match.group(5), match.group(4) or match.group(6)
        values = [chr(c) for c in range(ord(first), ord(last) + 1, step)]
    return values or None


def _transfer_ip(text: str):
    """The IP address a string holds, brackets allowed; None when it holds none."""
    import ipaddress
    try:
        return ipaddress.ip_address(text.strip().strip('[]'))
    except ValueError:
        return None


def _transfer_curl_dial(url: str, connects: List[str], pins: List[str]) -> Optional[tuple]:
    """(the host a URL's request connects to, the addresses pinned for it), as curl applies the first matching
    --connect-to and then the last --resolve pin for that host and port, a named host before *; None when neither."""
    host = _transfer_url_host(url, _TRANSFER_CURL_SCHEMES)
    try:
        parts = _transfer_url_split(url)
        port = str(parts.port or _TRANSFER_DEFAULT_PORTS.get(parts.scheme.lower(), ''))
    except ValueError:
        return None
    target = (host, port)
    for rule in connects:
        fields = re.split(r':(?![^\[]*\])', rule)  # colons inside [ ] belong to an IPv6 address
        if len(fields) == 4 and _transfer_clean_host(fields[0]) in ('', host) and fields[1] in ('', port):
            target = (_transfer_clean_host(fields[2]) or host, fields[3] or port)
            break
    pinned = {}
    for pin in pins:
        fields = re.split(r':(?![^\[]*\])', pin.lstrip('+-'))
        key = ('*' if fields[0] == '*' else _transfer_clean_host(fields[0]), fields[1] if len(fields) > 1 else '')
        pinned.pop(key, None)
        if not pin.startswith('-') and len(fields) > 2:
            pinned[key] = [ip for ip in map(_transfer_ip, ':'.join(fields[2:]).split(',')) if ip]
    addresses = pinned.get(target) or pinned.get(('*', target[1])) or []
    if target[0] == host and not addresses:
        return None
    return (str(addresses[0]) if addresses else target[0]), addresses


def _transfer_curl_request(args: List[str], i: int) -> tuple:
    """(the URLs of the curl request at args[i], whether it sends data, its --resolve and --connect-to values, whether
    it turns globbing off, where the next request starts, (the kind of proxy it names, empty for none and None when
    it names none, its --noproxy value), its --proto-default scheme); a --next that is an option's value does not
    end it."""
    urls, flags, method, overrides, scheme = [], set(), '', [], ''
    kind, preproxy, noproxy = None, None, None
    while i < len(args):
        arg, value, i = args[i], None, i + 1
        if arg == '--':
            urls, i = urls + args[i:], len(args)  # every word after it is a URL, a --next too
            break
        if arg in ('-:', '--next'):
            break
        if arg.startswith('--'):
            # curl reads --name=value as --name value, and --expand-name as --name with variables expanded.
            arg, eq, attached = arg.partition('=')
            arg = '--' + arg[len('--expand-'):] if arg.startswith('--expand-') else arg
            if eq:
                value = attached
            elif arg in _TRANSFER_CURL_LONG_VALUES and i < len(args):
                value, i = args[i], i + 1
        elif arg.startswith('-') and len(arg) > 1:
            arg, value, i = _transfer_short_option(arg, args, i, _TRANSFER_CURL_SHORT_VALUES, flags)
        else:
            urls.append(arg)
            continue
        flags.add(arg)
        flags -= _TRANSFER_CURL_UNDOES.get(arg, set())
        if arg == '--url' and value:
            urls.append(value)
        elif arg in ('-X', '--request') and value:
            method = value.upper()
        elif arg in ('--resolve', '--connect-to') and value:
            overrides.append((arg, value))
        elif arg == '--preproxy' and value is not None:
            preproxy = _transfer_proxy_kind(value, 'socks4a')  # curl sends a scheme-less one the name
        elif arg in _TRANSFER_CURL_PROXIES and value is not None:
            # An empty one turns the proxy off; a --socks option names its kind, and -x its URL's scheme.
            kind = '' if not value.strip() else _TRANSFER_CURL_PROXIES[arg] or _transfer_proxy_kind(value)
        elif arg == '--noproxy' and value is not None:
            noproxy = value
        elif arg == '--proto-default' and value is not None:
            scheme = value.strip().lower()
    sends = flags & _TRANSFER_CURL_UPLOADS or method in _TRANSFER_SENDING_METHODS or \
        (flags & _TRANSFER_CURL_BODIES and not flags & {'-G', '--get'})
    # Without -x, a --preproxy is the SOCKS proxy the request goes through.
    return urls, bool(sends), overrides, bool(flags & {'-g', '--globoff'}), i, \
        (kind if kind is not None else preproxy, noproxy), scheme


def _transfer_wget(args: List[str], proxied: bool = False) -> List[tuple]:
    """wget's URLs: sent to when it posts data or a file; else fetched from. Each carries whether it goes through a
    proxy: one the command set or an -e proxy setting, unless --no-proxy or -e use_proxy=off turns proxies off."""
    urls, flags, settings, i = [], set(), {}, 0
    while i < len(args):
        arg, name, value, i = args[i], None, None, i + 1
        if arg == '--':
            urls.extend(args[i:])  # every word after it is a URL
            break
        if arg.startswith('--'):
            name, eq, value = arg.partition('=')
            if not eq and name in _TRANSFER_WGET_LONG_VALUES:
                value, i = (args[i] if i < len(args) else None), i + 1
            flags.add(name)
        elif arg.startswith('-') and len(arg) > 1:
            name, value, i = _transfer_short_option(arg, args, i, _TRANSFER_WGET_SHORT_VALUES, flags)
            flags.add(name)
        else:
            urls.append(arg)
        if name in ('-e', '--execute') and value:
            key, _, setting = value.replace(' ', '').lower().partition('=')
            settings[key.replace('_', '')] = setting
    on = settings.get('useproxy', 'on') in ('on', 'yes', '1') and '--no-proxy' not in flags
    proxy = on and (proxied or any(settings.get(k) for k in ('httpproxy', 'httpsproxy', 'ftpproxy')))
    direction = 'out' if flags & _TRANSFER_WGET_UPLOADS else 'in'
    return [(direction, _transfer_url_host(url, _TRANSFER_WGET_SCHEMES), None, None, proxy) for url in urls]


def _transfer_ssh_args(program: str, args: List[str], switches: Optional[set] = None) -> tuple:
    """(operands, the options that change which host or user ssh -G resolves) for ssh, scp or sftp; switches, when
    given, collects the flags such as -n, and the first -o StdinNull as StdinNull=yes, =no, or =bad for a value ssh
    rejects."""
    passthrough, operands, i = [], [], 0
    switches = set() if switches is None else switches
    value_flags = _TRANSFER_SSH_VALUE_FLAGS[program]
    # scp's -l is a bandwidth limit, not a login.
    identity_flags = ('l', 'o', 'F', 'J', 'p') if program == 'ssh' else ('o', 'F', 'J', 'P')
    while i < len(args):
        arg, i = args[i], i + 1
        # ssh reads options before and right after its destination; the first other word starts the remote command.
        reading_options = not operands or (program == 'ssh' and len(operands) == 1)
        if not reading_options or not arg.startswith('-') or arg == '-':
            operands.append(arg)
            continue
        if arg == '--':
            operands.extend(args[i:])
            break
        flag, value, i = _transfer_short_option(arg, args, i, value_flags, switches)
        option = re.split(r'[\s=]', (value or '').strip(), maxsplit=1)[0].lower()
        if flag == '-o' and option == 'stdinnull':
            # The first counts. ssh takes yes or true and no or false, and runs nothing for any other value, wherever.
            setting = {'yes': 'yes', 'true': 'yes', 'no': 'no', 'false': 'no'}.get(
                re.split(r'[\s=]+', value.strip(), maxsplit=1)[-1].lower(), 'bad')
            if setting == 'bad' or not switches & {'StdinNull=yes', 'StdinNull=no'}:
                switches.add('StdinNull=' + setting)
        if value and flag[1:] in identity_flags and (flag != '-o' or option in _TRANSFER_SSH_IDENTITY_OPTIONS):
            passthrough += ['-p' if flag == '-P' else flag, value]
    return operands, passthrough


def _transfer_rsync_args(args: List[str], env: Dict) -> tuple:
    """(operands, ssh options for its remote shell, or None when that shell isn't ssh) for rsync."""
    shell, operands, i = _transfer_env(env, 'RSYNC_RSH'), [], 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == '--':
            operands.extend(args[i:])  # every word after it is an operand
            break
        if arg == '--rsh' and i < len(args):
            shell, i = args[i], i + 1
        elif arg.startswith('--rsh='):
            shell = arg.split('=', 1)[1]
        elif arg in _TRANSFER_RSYNC_VALUE_OPTIONS:
            i += 1
        elif arg.startswith('-') and not arg.startswith('--'):
            flag, value, i = _transfer_short_option(arg, args, i, _TRANSFER_SSH_VALUE_FLAGS['rsync'], set())
            shell = value if flag == '-e' else shell
        elif not arg.startswith('-'):
            operands.append(arg)
    if not shell:
        return operands, []
    words = _transfer_words(shell)
    if not words or _transfer_program_name(words[0]) != 'ssh':
        return operands, None
    return operands, _transfer_ssh_args('ssh', words[1:] + ['-'])[1]


def _transfer_remote(arg: str) -> Optional[tuple]:
    """(destination, port, whether ssh carries it) for a remote copy operand; None for a local path."""
    uri = re.match(r'^(scp|sftp|rsync)://(?:([^@/;:]+)(?:[;:][^@/]*)?@)?(\[[^\]/]+\]|[^/:\[\]@]+)(?::(\d+))?(?=/|$)', arg)
    if uri:
        # A URI names the login and port itself; anything after the user (a password) is dropped.
        destination = uri.group(2) + '@' + uri.group(3) if uri.group(2) else uri.group(3)
        return destination, uri.group(4), uri.group(1) != 'rsync'
    if '://' in arg:
        return None
    # A bracketed host may hold an IPv6 address; a second colon after the host marks an rsync daemon.
    match = re.match(r'^((?:[^@/:\[\]]+@)?(?:\[[^\]/]+\]|[^/:\[\]]+)):(:)?', arg)
    # A drive letter is a local path only on Windows; elsewhere scp dials host C.
    if not match or (os.name == 'nt' and re.match(r'^[A-Za-z]:[\\/]', arg)):
        return None
    return match.group(1), None, not match.group(2)


def _transfer_copy(program: str, args: List[str], env: Dict) -> List[tuple]:
    """Each remote side of an scp, sftp or rsync copy: fetched from as a source, sent to as the target."""
    operands, options = _transfer_rsync_args(args, env) if program == 'rsync' else _transfer_ssh_args(program, args)
    remotes = [_transfer_remote(op) for op in operands]
    if program == 'sftp' and operands:
        # sftp takes one destination: a bare host opens a session, a host:path or URI fetches that path.
        plain = re.match(r'^(?:[^@/:\[\]]+@)?(?:\[[^\]/]+\]|[^/:\[\]]+)$', operands[0])
        remotes = [((operands[0], None, True) if plain else remotes[0], '' if plain else 'in')]
    elif len(remotes) == 1:
        remotes = [(remotes[0], 'in' if program == 'rsync' else '')]  # rsync lists a lone remote
    else:
        remotes = [(r, 'in') for r in remotes[:-1]] + [(remotes[-1], 'out')] if remotes else []
    endpoints = []
    for remote, direction in remotes:
        if remote:
            destination, port, via_ssh = remote
            ssh_options = (options + (['-p', port] if port else [])) if via_ssh and options is not None else None
            endpoints.append((direction, destination, ssh_options))
    return endpoints


def _transfer_ssh_pipe(args: List[str], sends: bool, receives: bool) -> List[tuple]:
    """ssh used as a pipe: sent to when its stdin is fed in, fetched from when its stdout is kept. -n, -f, which implies
    it, and a first -o StdinNull=yes keep stdin unread; ForkAfterAuthentication=yes still sends it."""
    switches = set()
    operands, options = _transfer_ssh_args('ssh', args, switches)
    if not operands or 'StdinNull=bad' in switches:
        return []
    sends = sends and not switches & {'-n', '-f', 'StdinNull=yes'}
    return [(d, operands[0], options) for d, used in (('out', sends), ('in', receives)) if used]


def _transfer_netcat(args: List[str], sends: bool) -> List[tuple]:
    """nc's host: sent to when its stdin is fed in; a listener reaches no host. ncat's --proxy, or OpenBSD nc's -x,
    reaches it through a proxy that resolves the name, unless ncat's --proxy-dns local or both, or nc's -X 4 (SOCKS4),
    resolves it here; -X with no -x connects directly."""
    positional, flags, values, i = [], set(), {}, 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == '--':
            positional.extend(args[i:])  # every word after it is an operand
            break
        if arg.startswith('--'):
            name, eq, value = arg.partition('=')  # --proxy=host:port is --proxy
            if not eq and name in _TRANSFER_NC_LONG_VALUES:
                value, i = (args[i] if i < len(args) else ''), i + 1
            flags.add(name)
            values[name] = value.lower()
        elif arg.startswith('-') and len(arg) > 1:
            flag, value, i = _transfer_short_option(arg, args, i, _TRANSFER_NC_SHORT_VALUES, flags)
            flags.add(flag)
            values[flag] = (value or '').lower()
        else:
            positional.append(arg)
    if not positional or flags & {'-l', '--listen', '-U', '--unixsock'}:
        return []
    if '--proxy' in flags:
        remote = values.get('--proxy-dns') not in ('local', 'both')  # SOCKS4 too sends ncat the name
    else:
        remote = '-x' in flags and values.get('-X') != '4'
    return [('out' if sends else '', positional[0], None, None, remote)]

def _transfer_socat(args: List[str], sends: bool) -> List[tuple]:
    """The hosts socat's two addresses connect to: sent to when its stdin is fed in."""
    addresses, i = [], 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg in _TRANSFER_SOCAT_VALUE_OPTIONS:
            i += 1
        elif arg == '-' or not arg.startswith('-'):
            addresses.append(arg)
    endpoints = []
    for address in addresses[:2]:
        target = _transfer_socat_target(address)
        if target:
            endpoints.append(('out' if sends else '', target[0], None, None, target[1]))
    return endpoints


def _transfer_socat_target(address: str) -> Optional[tuple]:
    """(the host a socat address connects to, whether a proxy reaches it), read from its colon fields, a bracketed
    address being one field; None for an address that connects to none, or one socat rejects."""
    body, *options = re.split(r',(?![^\[]*\])', address)
    kind, *fields = re.split(r':(?![^\[]*\])', body)
    kind, options = kind.lower(), {o.split('=', 1)[0].strip().lower() for o in options}
    # Each type's fields, the target's place among them, and whether a proxy reaches it. SOCKS4 sends the server an
    # address, so socat looks the target up itself; SOCKS4A and SOCKS5 send the name.
    shape = {'proxy': (3, 1, True), 'proxy-connect': (3, 1, True), 'socks4': (3, 1, False), 'socks4a': (3, 1, True),
             'socks5': (4, 2, True), 'socks5-connect': (4, 2, True)}.get(kind)
    if shape is None and re.fullmatch(r'(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?', kind):
        # A proxy option on a direct address is one socat refuses, so it connects nowhere.
        shape = None if options & {'proxyport', 'socksport'} else (2, 0, False)
    if shape is None or len(fields) != shape[0]:
        return None
    return fields[shape[1]], shape[2]

def _transfer_httpie_item(item: str) -> bool:
    """Whether an HTTPie request item is data (=, :=, @, =@, :=@) rather than a header (:) or a query (==)."""
    match = re.match(r'^(?:\\.|[^\\=:@])*(:=@|=@|:=|==|=|@|:)', item)
    return bool(match) and match.group(1) not in ('==', ':')


def _transfer_httpie(args: List[str], sends: bool, proxied: bool = False) -> List[tuple]:
    """HTTPie's URL: sent to when the request carries data or a sending method; else fetched from. It goes through a
    proxy with --proxy or one the command set."""
    positional, flags, i = [], set(), 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == '--':
            positional.extend(args[i:])  # every word after it is an operand
            break
        if arg.startswith('--'):
            name, eq, _ = arg.partition('=')
            if not eq and name in _TRANSFER_HTTPIE_LONG_VALUES:
                i += 1
            flags.add(name)
        elif arg.startswith('-') and len(arg) > 1:
            flag, _, i = _transfer_short_option(arg, args, i, _TRANSFER_HTTPIE_SHORT_VALUES, flags)
            flags.add(flag)
        else:
            positional.append(arg)
    if not positional or '--offline' in flags:
        return []
    method = positional[0].upper() if len(positional) > 1 and re.match(r'^[A-Za-z]+$', positional[0]) else ''
    url, items = (positional[1], positional[2:]) if method else (positional[0], positional[1:])
    reads_stdin = sends and not flags & {'-I', '--ignore-stdin'}
    out = method in _TRANSFER_SENDING_METHODS or '--raw' in flags or reads_stdin or any(map(_transfer_httpie_item, items))
    host = 'localhost' if url.startswith(':') else _transfer_url_host(url, _TRANSFER_HTTPIE_SCHEMES)
    return [('out' if out else 'in', host, None, None, proxied or '--proxy' in flags)]


def _transfer_ps_parameter(name: str) -> str:
    """The web cmdlet parameter a -Name binds to, as PowerShell resolves it: an exact name or alias, else the one
    parameter it starts, the cmdlet's own before the common ones; empty when it starts several, which PowerShell
    rejects, and the name itself when it starts none."""
    name = name.lower()
    if name in _TRANSFER_PS_OWN or name in _TRANSFER_PS_COMMON:
        return name
    if name in _TRANSFER_PS_ALIASES:
        return _TRANSFER_PS_ALIASES[name]
    for group in (_TRANSFER_PS_OWN, _TRANSFER_PS_COMMON):
        found = [parameter for parameter in group if parameter.startswith(name)]
        if found:
            return found[0] if len(found) == 1 else ''
    return name


def _transfer_web_cmdlet(args: List[str], sends: bool, proxied: bool = False) -> List[tuple]:
    """Invoke-WebRequest's or Invoke-RestMethod's URI: sent to with a body, file, form, piped input or sending
    method; else fetched from. It goes through a proxy with -Proxy, or one the command set unless -NoProxy."""
    uri, out, positional, proxy, i = '', sends, [], None, 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == '--':
            positional.extend(args[i:])  # PowerShell's end of parameters: every word after it is an argument
            break
        if not re.match(r'^-[A-Za-z]', arg):
            positional.append(arg)
            continue
        name, colon, value = arg[1:].partition(':')
        name = _transfer_ps_parameter(name)
        if not name:
            return []  # a name that starts several parameters, which PowerShell rejects
        if not colon and name not in _TRANSFER_PS_SWITCHES and i < len(args):
            value, i = args[i], i + 1
        if name == 'uri':
            uri = value
        elif name in ('body', 'infile', 'form'):
            out = True
        elif name in ('method', 'custommethod') and value.upper() in _TRANSFER_SENDING_METHODS:
            out = True
        elif name in ('proxy', 'noproxy'):
            proxy = bool(value) if name == 'proxy' else proxy or False
    uri = uri or (positional[0] if positional else '')
    proxy = proxied if proxy is None else proxy
    return [('out' if out else 'in', _transfer_url_host(uri, _TRANSFER_POWERSHELL_SCHEMES), None, None, proxy)] if uri \
        else []


def _transfer_stdio(layers: tuple) -> tuple:
    """(whether a call's stdin is fed from a file or pipe, whether its stdout goes to one), from the pipes and
    redirections around it applied as the shell does: the outermost first, each one's pipes before its redirections."""
    fds = {0: 'null', 1: 'null', 2: 'null'}  # the agent's own stdin and stdout carry no transfer
    for piped_in, piped_out, redirections in reversed(layers):
        if piped_in:
            fds[0] = 'pipe'
        if piped_out:
            fds[1] = 'pipe'
        for fd, value in redirections:
            fds[fd] = fds.get(value, 'null') if isinstance(value, int) else value
    return fds[0] in ('file', 'pipe'), fds[1] in ('file', 'pipe')


def _transfer_parse(program: str, args: List[str], env: Dict, other_user: bool, layers: tuple) -> Optional[tuple]:
    """(tool, [(direction, destination, ssh -G options or None[, curl's dial])]) for a transfer command; None for any
    other."""
    tool, (sends, keeps) = _TRANSFER_TOOLS.get(program), _transfer_stdio(layers)
    if tool in ('scp', 'sftp', 'rsync'):
        raw = _transfer_copy(tool, args, env)
    elif tool == 'ssh':
        raw = _transfer_ssh_pipe(args, sends, keeps)
    elif tool in ('curl', 'wget'):
        args = _transfer_stdin_args(tool, args, _transfer_stdin_text(layers))
        raw = _transfer_curl(args, env) if tool == 'curl' else _transfer_wget(args, _transfer_proxied(env))
    elif tool in ('nc', 'socat'):
        raw = _transfer_netcat(args, sends) if tool == 'nc' else _transfer_socat(args, sends)
    elif tool in ('httpie', 'powershell'):
        raw = (_transfer_httpie if tool == 'httpie' else _transfer_web_cmdlet)(args, sends, _transfer_proxied(env))
    else:
        return None
    # Under sudo, ssh runs as that user, with that user's config, which this can't read.
    return tool, [(e[0], e[1], None if other_user else e[2]) + e[3:] for e in raw]


def _transfer_clean_host(host: str) -> str:
    """A host name or address in lower case without brackets; empty when it isn't one."""
    import ipaddress
    host = host.strip().lower()
    host = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    if re.match(r'^[a-z0-9_][a-z0-9_.-]{0,252}$', host):
        return host
    try:
        return str(ipaddress.ip_address(host.split('%')[0])) if ':' in host else ''
    except ValueError:
        return ''


def _transfer_home() -> str:
    """The home folder ssh reads its config from: the account's own, which $HOME does not change."""
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser('~')


def _transfer_ssh_config_words(line: str) -> Optional[List[str]]:
    """An ssh config line split the way OpenSSH splits it; None for an unbalanced quote, which ssh rejects."""
    words, word, in_word, quote, i = [], '', False, None, 0
    while i < len(line):
        ch = line[i]
        # A backslash escapes a quote, a backslash, or (outside quotes) a space; any other backslash is kept.
        if ch == '\\' and i + 1 < len(line) and (line[i + 1] in '\'"\\' or (quote is None and line[i + 1] == ' ')):
            word, in_word, i = word + line[i + 1], True, i + 2
            continue
        if quote is not None:
            if ch == quote:
                quote = None
            else:
                word += ch
        elif ch in '\'"':
            quote, in_word = ch, True
        elif ch in ' \t':
            if in_word:
                words.append(word)
            word, in_word = '', False
        elif ch == '#' and not in_word:
            break
        else:
            word, in_word = word + ch, True
        i += 1
    if quote is not None:
        return None
    if in_word:
        words.append(word)
    return words


def _transfer_match_execs(words: List[str]) -> bool:
    """Whether a Match line's criteria include exec, read as ssh reads them: each a keyword, negated with !, taking an
    argument after a space or = unless it is all, canonical or final."""
    i = 0
    while i < len(words):
        criterion, eq, _ = words[i].partition('=')
        criterion = criterion.lower().lstrip('!')
        if criterion == 'exec':
            return True
        i += 1 if eq or criterion in ('all', 'canonical', 'final') else 2
    return False


def _transfer_ssh_config_line(line: str, homes: List[str], bases: tuple) -> Optional[tuple]:
    """One ssh config line read as ssh reads it: (whether it is an Include, the files it names, resolved against every
    home and folder ssh may use); None when it could run a command or a DNS lookup, or ssh may read it differently."""
    import glob
    # ssh joins no lines, but a line ending in a backslash is refused too, as a reader that joins them would differ.
    odd = re.search(r'[\x00-\x08\x0a-\x1f\x7f]', line) or line.rstrip(' \t').endswith('\\')
    words = _transfer_ssh_config_words(line) if not odd else None
    if words is None:
        return None
    if not words:
        return False, []
    keyword, _, attached = words[0].partition('=')
    keyword = keyword.lower()
    # ssh allows `Keyword=value` and `Keyword =value`, so a leading = is only a separator.
    words = [w.lstrip('=') for w in ([attached] if attached else []) + words[1:] if w.lstrip('=')]
    if keyword == 'match' and _transfer_match_execs(words):
        return None
    if keyword == 'canonicalizehostname' and words and words[0].lower() in ('yes', 'always'):
        return None
    if keyword != 'include':
        return False, []
    paths = []
    for pattern in words:
        if '$' in pattern or '%' in pattern:
            return None  # ssh may expand a variable or token here
        # ssh globs the path, and glob reads a backslash as escaping the next character.
        pattern = re.sub(r'\\(.)', r'\1', pattern)
        if pattern == '~' or pattern.startswith('~/'):
            candidates = [home + pattern[1:] for home in homes]
        else:
            candidates = [os.path.join(base, os.path.expanduser(pattern)) for base in bases]
        for candidate in candidates:
            paths += sorted(glob.glob(candidate))
    return True, paths


def _transfer_ssh_system_dir() -> str:
    """The folder of the system config the ssh on PATH reads: its install prefix's etc/ssh, /etc/ssh for one in /usr,
    and PROGRAMDATA's ssh on Windows."""
    import shutil
    if os.name == 'nt':
        return os.path.join(os.environ.get('PROGRAMDATA') or '', 'ssh')
    prefix = os.path.dirname(os.path.dirname(shutil.which('ssh') or '/usr/bin/ssh'))
    return '/etc/ssh' if prefix in ('/usr', '/') else os.path.join(prefix, 'etc', 'ssh')


def _transfer_ssh_vetted(options: List[str], cwd: Optional[str], folder: str) -> Optional[List[str]]:
    """ssh -G's options with -F set to a copy, in folder, of exactly the configs this read once and checked, with each
    Include pointed at the copies, so ssh reads nothing else; None when one could run a command or can't be checked."""
    import stat
    home = _transfer_home()
    # ssh reads ~/.ssh/config from the account's home but expands an Include's ~ and relative path with $HOME.
    homes = list(dict.fromkeys([home, os.path.expanduser('~')]))
    user_bases = tuple(os.path.join(h, '.ssh') for h in homes)
    if len(options) % 2:
        return None
    pairs = list(zip(options[::2], options[1::2]))
    configs = [os.path.expanduser(value) for flag, value in pairs if flag == '-F']
    rest = [word for flag, value in pairs if flag != '-F' for word in (flag, value)]
    if configs and configs[-1] == 'none':
        return options
    if configs and not (os.path.isabs(configs[-1]) or (cwd and os.path.isdir(cwd))):
        return None
    system = _transfer_ssh_system_dir()
    # ssh reads only a -F file; else the user's config, then the system's.
    sources = [(os.path.join(cwd or '', configs[-1]), user_bases)] if configs else \
        [(os.path.join(home, '.ssh', 'config'), user_bases), (os.path.join(system, 'ssh_config'), (system,))]
    copies, queue = {}, []

    def copy_of(path: str, bases: tuple) -> str:
        if (path, bases) not in copies:
            copies[(path, bases)] = os.path.join(folder, str(len(copies)))
            queue.append((path, bases))
        return copies[(path, bases)]

    tops = [copy_of(path, bases) for path, bases in sources]
    while queue:
        path, bases = queue.pop(0)
        if len(copies) > _TRANSFER_SSH_CONFIG_MAX_FILES:
            return None
        try:
            # Read once, without blocking on a fifo; only a small regular file is read.
            handle = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
            try:
                info = os.fstat(handle)
                if not stat.S_ISREG(info.st_mode) or info.st_size > _TRANSFER_SSH_CONFIG_MAX_BYTES:
                    return None
                data = os.read(handle, _TRANSFER_SSH_CONFIG_MAX_BYTES + 1)
            finally:
                os.close(handle)
        except FileNotFoundError:
            if configs:
                return None  # ssh refuses a -F file that isn't there
            data = b''
        except OSError:
            return None
        if len(data) > _TRANSFER_SSH_CONFIG_MAX_BYTES:
            return None
        lines = []
        for line in data.decode('utf-8', 'surrogateescape').split('\n'):
            line = line[:-1] if line.endswith('\r') else line
            read = _transfer_ssh_config_line(line, homes, bases)
            if read is None:
                return None
            lines.append(line if not read[0] else
                         'Include ' + ' '.join('"%s"' % copy_of(found, bases) for found in read[1]) if read[1] else '')
        with open(copies[(path, bases)], 'w', encoding='utf-8', errors='surrogateescape') as out:
            out.write('\n'.join(lines) + '\n')
    top = tops[0]
    if not configs:
        top = os.path.join(folder, 'config')
        with open(top, 'w', encoding='utf-8') as out:
            out.write(''.join('Include "%s"\n' % copy for copy in tops))
    return ['-F', top] + rest


def _transfer_ssh_jumps(options: List[str]) -> bool:
    """Whether ssh options send the connection through a jump host or a proxy command, which reach the host from there."""
    for flag, value in zip(options[::2], options[1::2]):
        if flag not in ('-J', '-o'):
            continue
        key, setting = ('proxyjump', value) if flag == '-J' else (re.split(r'[\s=]+', value.strip(), 1) + [''])[:2]
        if key.lower() in ('proxyjump', 'proxycommand') and setting.strip().lower() not in ('', 'none'):
            return True
    return False


def _transfer_ssh_hostname(destination: str, options: List[str], cwd: Optional[str], state: Dict) -> tuple:
    """(the host ssh connects to for a destination, read from ssh -G, empty when it can't be looked up safely, whether
    ssh -G reports a jump host or proxy command for it)."""
    configs = [v for i, v in enumerate(options) if i and options[i - 1] == '-F']
    if any(v.startswith(('~', _TRANSFER_SUBSTITUTED)) for v in configs):
        return '', False  # a HOME not known, or a ~ the shell left, which ssh reads as it is, as in rsync -e
    key = ('ssh', destination, tuple(options), cwd)
    if key not in state:
        state[key] = '', False
        # A destination starting with - would reach ssh -G as an option.
        if not destination.startswith('-'):
            target = destination.replace('[', '').replace(']', '')
            out = _transfer_run(['ssh', '-G'] + options + ['--', target], cwd, state) or ''
            names = [line.split(None, 1)[1] for line in out.splitlines() if line.startswith('hostname ')]
            jumps = any(line.startswith(('proxyjump ', 'proxycommand ')) for line in out.splitlines())
            state[key] = (_transfer_clean_host(names[0]) if names else ''), jumps
    return state[key]


def _transfer_kind(address) -> str:
    import ipaddress
    address = getattr(address, 'ipv4_mapped', None) or address
    for kind, networks in _TRANSFER_ADDRESS_KINDS:
        if any(address in ipaddress.ip_network(n) for n in networks):
            return kind
    return 'public'


def _transfer_resolve(host: str, timeout: float) -> list:
    """The host's addresses from the system resolver; [] when it fails or takes longer than timeout."""
    import ipaddress
    import socket
    import threading
    found = []

    def lookup():
        try:
            for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                found.append(ipaddress.ip_address(info[4][0].split('%')[0]))
        except Exception:
            pass

    # A daemon thread, so a resolver that hangs past the timeout never holds the hook open.
    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return [] if worker.is_alive() else list(found)


def _transfer_address(host: str, state: Dict, lookup: bool = True) -> str:
    """The kind of address a host resolves to, looked up once per turn: public when any address is public, else
    the first address's kind; unresolved when the lookup fails, the turn's budget is spent, or lookup is off."""
    import ipaddress
    try:
        return _transfer_address_kind([ipaddress.ip_address(host)])
    except ValueError:
        pass
    if not lookup:
        return 'unresolved'  # whatever an earlier call found: this one may not have run, or a proxy reaches the host
    key = ('address', host)
    if key not in state:
        remaining = _transfer_deadline(state) - time.monotonic()
        state[key] = _transfer_address_kind(
            _transfer_resolve(host, min(_TRANSFER_DNS_TIMEOUT, remaining)) if remaining > 0 else [])
    return state[key]


def _transfer_address_kind(addresses: list) -> str:
    """public when any address is public, else the first address's kind; unresolved when there is none."""
    kinds = [_transfer_kind(a) for a in addresses]
    return 'unresolved' if not kinds else 'public' if 'public' in kinds else kinds[0]


def _transfer_endpoint(raw: tuple, cwd: Optional[str], state: Dict, lookup: bool = True) -> Optional[Dict]:
    """One place a transfer reached, from (direction, destination, ssh -G options or None[, curl's dial[, whether a
    proxy reaches it]]): the host as written without a login, the host it connects to (ssh -G or curl's dial), and that
    host's address kind. Without lookup, neither ssh -G nor DNS runs, and only an address as written is classified; a
    host a proxy or jump host reaches is never looked up here either."""
    direction, destination, ssh_options = raw[:3]
    dial = raw[3] if len(raw) > 3 else None
    lookup = lookup and not (len(raw) > 4 and raw[4])
    destination = destination.strip()
    host = _transfer_url_host(destination, _TRANSFER_CURL_SCHEMES) if '://' in destination else \
        destination.rsplit('@', 1)[-1]
    host = _transfer_clean_host(host)
    if not host:
        return None
    if dial:
        resolved = dial[0]
        address = _transfer_address_kind(dial[1]) if dial[1] else _transfer_address(dial[0], state, lookup)
    else:
        lookup = lookup and not (ssh_options is not None and _transfer_ssh_jumps(ssh_options))
        resolved, jumps = _transfer_ssh_hostname(destination, ssh_options, cwd, state) if ssh_options is not None and \
            lookup else ('', False)
        # Through a jump host or proxy command the bytes go where it sends them, not to the config's HostName.
        resolved = host if jumps else resolved or host
        address = _transfer_address(resolved, state, lookup and not jumps)
    endpoint = {'direction': direction, 'host': host, 'resolved_host': resolved, 'address': address}
    return {k: v for k, v in endpoint.items() if v}


def _transfer(command: Optional[str], cwd: Optional[str], state: Dict) -> Optional[Dict]:
    """Where a shell call's transfers went: the first transfer tool it ran and each place it sent to or fetched
    from; None when it ran no transfer. Never raises, and never takes longer than the turn's budget."""
    try:
        if not isinstance(command, str) or not command.strip():
            return None
        tool, endpoints = None, []
        for program, args, env, call_cwd, other_user, layers, unsure in \
                _transfer_walk(_TransferLexer(command).read() or [], cwd, {}, 0):
            found = _transfer_parse(program, args, env, other_user, layers)
            for raw in (found[1] if found else []):
                if len(endpoints) >= _TRANSFER_MAX_ENDPOINTS:
                    break
                endpoint = _transfer_endpoint(raw, call_cwd, state, not unsure)
                if endpoint and endpoint not in endpoints:
                    endpoints.append(endpoint)
                    tool = tool or found[0]
        return {'tool': tool, 'endpoints': endpoints} if endpoints else None
    except Exception:
        return None


def _call_ts(stamp: Any) -> Optional[str]:
    """A log timestamp as ISO 8601 UTC to the second, such as 2026-10-22T16:40:00Z; None when it can't be read."""
    from datetime import datetime, timezone
    try:
        match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$', str(stamp).strip())
        if not match:
            return None
        moment = datetime.fromisoformat(match.group(1) + ('+00:00' if match.group(2) in (None, 'Z') else match.group(2)))
        return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return None


def _with_call_ts(entry: Dict, stamp: Any) -> Dict:
    """The tool_use entry with the time its call was logged, when that time can be read."""
    ts = _call_ts(stamp)
    if ts:
        entry['ts'] = ts
    return entry
# --- end transfer resolution ---


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
    transfer_state = {}

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
            if shaped.get('tool_name') == 'Bash' and isinstance(shaped.get('tool_input'), dict):
                # A launch-process is a new process in its own cwd, relative to the workspace root; no cd carries over.
                call_cwd = (ev.get('tool_input') or {}).get('cwd') if isinstance(ev.get('tool_input'), dict) else None
                start = os.path.join(cwd or '', call_cwd) if isinstance(call_cwd, str) and call_cwd else cwd
                start = start if start and os.path.isabs(start) else None
                # A blocked or denied call, or one that failed to launch, has an error but no return code: it never ran.
                ran = not ev.get('tool_error') or '<return-code>' in str(ev.get('tool_error'))
                transfer = _transfer(shaped['tool_input'].get('command'), start, transfer_state) if ran else None
                if transfer:
                    shaped['transfer'] = transfer
            assistant_tool_uses.append(_with_call_ts(shaped, log_entry.get('timestamp')))

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


def _is_windows() -> bool:
    return os.name == "nt"


def _machine_env(name: str) -> Optional[str]:
    """Windows: read HKLM directly, since os.getenv() would let a per-user setx shadow it."""
    if not _is_windows():
        return os.environ.get(name)
    try:
        import winreg
    except ImportError:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


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


def _ensure_discovery_installer(installer_path: Path, installer_url: str,
                                category: str = 'discovery_gate') -> bool:
    """Download or TTL-refresh the installer. False only when nothing usable is on disk."""
    DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    if not _discovery_installer_is_stale(installer_path):
        return True
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
            os.chmod(tmp, 0o700)
        os.replace(tmp, installer_path)
        return True
    tmp.unlink(missing_ok=True)
    if not installer_path.exists():
        log_error(f"discovery {installer_path.name} download failed: {r.stderr.decode(errors='replace')[:200]}", category)
        return False
    log_error(f"discovery {installer_path.name} refresh failed; using cached copy: {r.stderr.decode(errors='replace')[:200]}", category)
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
        unbound_config = {}
        try:
            with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
                unbound_config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log_error("mcp scan dispatch: config unreadable, trying env: %s errno=%s"
                      % (type(e).__name__, getattr(e, "errno", None)), 'mcp_server')
        if not isinstance(unbound_config, dict):
            unbound_config = {}
        api_key = unbound_config.get("api_key")
        backend_url = unbound_config.get("base_url")
        if not (api_key and backend_url):
            api_key = _machine_env('UNBOUND_AUGMENT_API_KEY')
            backend_url = _machine_env('UNBOUND_BACKEND_URL')
            if backend_url and not backend_url.startswith("https://"):
                log_error("mcp scan dispatch: env base_url is not https, ignoring", 'mcp_server')
                backend_url = None
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
        elif _is_windows():
            # No bash and no install.sh on a stock Windows box, so the scan runs
            # through the PowerShell installer instead.
            installer_path, installer_url = _discovery_installer()
            if not _ensure_discovery_installer(installer_path, installer_url, 'mcp_server'):
                return
            scan_cmd = [
                _windows_system32_path("WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(installer_path),
                "-McpScan", "-McpServerName", server_name, "-Domain", backend_url,
            ]
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


def _relocate_state_dir(reason: str) -> Optional[str]:
    """Repoints cache/lock/marker at the fallback; returns the log message to defer."""
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
        return None
    DISCOVERY_CACHE_PATH = fallback / DISCOVERY_CACHE_PATH.name
    DISCOVERY_LOCK_PATH = fallback / DISCOVERY_LOCK_PATH.name
    DISCOVERY_DISPATCH_PATH = fallback / DISCOVERY_DISPATCH_PATH.name
    return "discovery gate: home state dir unusable (%s); using fallback" % reason


def _resolve_state_dir() -> Optional[str]:
    """Relocates if the state dir is unusable; returns the relocation message, if any."""
    reason = _state_dir_reject_reason(DISCOVERY_DISPATCH_PATH.parent)
    if reason is not None:
        return _relocate_state_dir(reason)
    return None


def _dispatch_discovery() -> None:
    try:
        relocation_message = _resolve_state_dir()
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

        if relocation_message:
            log_error(relocation_message, 'discovery_gate')

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
            unbound_config = {}
            try:
                with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
                    unbound_config = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                log_error("discovery gate: config unreadable, trying env: %s errno=%s"
                          % (type(e).__name__, getattr(e, "errno", None)), 'discovery_gate')
            if not isinstance(unbound_config, dict):
                unbound_config = {}
            api_key = unbound_config.get("api_key")
            backend_url = unbound_config.get("base_url")
            if not (api_key and backend_url):
                # Resolve as a unit -- never pair a config field with an env field.
                api_key = _machine_env('UNBOUND_AUGMENT_API_KEY')
                backend_url = _machine_env('UNBOUND_BACKEND_URL')
                if backend_url and not backend_url.startswith("https://"):
                    log_error("discovery gate: env base_url is not https, ignoring", 'discovery_gate')
                    backend_url = None
            if not api_key:
                log_error("discovery gate: no api_key in env or config", 'discovery_gate')
                return
            if not backend_url:
                log_error("discovery gate: no base_url in config or env", 'discovery_gate')
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
            try:
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
            except OSError as e:
                log_error("discovery gate: cache stamp failed: %s errno=%s"
                          % (type(e).__name__, e.errno), 'discovery_gate')
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
        input_data = _read_stdin()

        if not input_data:
            _emit('{"suppressOutput": true}')
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            _emit('{"suppressOutput": true}')
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
            try:
                identity = read_account_identity(event)
                _augment_plan(identity.get('user_email') if isinstance(identity, dict) else None,
                              probe=True)
            except Exception:
                pass  # the repo gate below must still print
            _dispatch_discovery()
            _emit(json.dumps(_repo_gate_session_start_output(event)))
            return
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            response["suppressOutput"] = True
            if not _emit(json.dumps(response)):
                _report_undelivered(hook_event_name, response)
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

        _emit('{"suppressOutput": true}')

    except Exception as e:
        # Still return empty JSON object to Augment to indicate completion
        log_error(f"Exception in main: {str(e)}", 'general')
        _emit('{"suppressOutput": true}')


if __name__ == '__main__':
    main()
