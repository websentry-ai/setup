#!/usr/bin/env python3
"""
Real-time Cursor hook event processor with smart garbage collection.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import json
import os
import stat
import subprocess
from pathlib import Path, PureWindowsPath
from collections import defaultdict
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re
import sqlite3
import shutil
import urllib.request
import platform
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote, urlparse

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

DISCOVERY_INSTALL_SH_TTL_SECONDS = 24 * 3600
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"
IDENTITY_CACHE_PATH = Path.home() / ".unbound" / "identity.json"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

# Use user's home directory for logs
LOG_DIR = Path.home() / ".cursor" / "hooks"
AUDIT_LOG = LOG_DIR / "agent-audit.log"
ERROR_LOG = LOG_DIR / "error.log"
LAST_REPORT_FILE = LOG_DIR / ".last_error_report"

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# discovery runs from the locally installed binary instead of a GitHub-fetched
# install.sh. UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without
# freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

PRETOOL_NATIVE_TOOLS = {'Delete', 'Write', 'Read'}   # preToolUse → policy check
EXCHANGE_NATIVE_TOOLS = {'Delete'}            # postToolUse → included in exchange
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_SEARCH_DIRS = (('.cursor', 'skills'), ('.agents', 'skills'),
                     ('.claude', 'skills'), ('.codex', 'skills'))
MANAGED_SKILLS_ROOT = Path.home() / '.cursor' / 'skills'
UNBOUND_SKILL_PREFIX = 'unbound-'
UNBOUND_SKILL_MARKER = '.unbound-managed'
SKILL_POLICY_STATE_ROOT = Path.home() / '.unbound' / 'skill-policy' / 'cursor'
SKILLS_SYNC_LOCK_PATH = SKILL_POLICY_STATE_ROOT / 'sync.lock'
SKILLS_SYNC_STALE_LOCK_SECONDS = 5 * 60
SKILLS_SYNC_TIMEOUT_SECONDS = 10
SKILL_POLICY_TOOL = 'cursor'
SKILL_POLICY_API_KEY_ENV = 'UNBOUND_CURSOR_API_KEY'
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CACHE_TTL_SECONDS = 300
# Repo-scope gate. Straying outside the allowed org is blocked on the first
# write, and the gate keeps no state on disk at all.
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100

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
    POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"


_cached_api_key = None
_reporting_error = False


SKILL_LOADED_WINDOW = 10
SKILL_TRANSCRIPT_TAIL_BYTES = 4 * 1024 * 1024


def _skill_policy_transcript_tail(path):
    try:
        with open(path, 'rb') as transcript_file:
            size = os.fstat(transcript_file.fileno()).st_size
            start = max(0, size - SKILL_TRANSCRIPT_TAIL_BYTES)
            transcript_file.seek(start)
            data = transcript_file.read(SKILL_TRANSCRIPT_TAIL_BYTES)
    except OSError:
        return []
    if start:
        boundary = data.find(b'\n')
        if boundary < 0:
            return []
        data = data[boundary + 1:]
    return data.splitlines()


def _skill_policy_valid_slug(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?', value))


def _managed_skill_dirs():
    try:
        return sorted(
            (
                entry for entry in MANAGED_SKILLS_ROOT.iterdir()
                if entry.is_dir() and not entry.is_symlink()
                and (entry / UNBOUND_SKILL_MARKER).is_file()
                and not (entry / UNBOUND_SKILL_MARKER).is_symlink()
            ),
            key=lambda entry: entry.name,
        )
    except Exception:
        return []


def _managed_skill_slug(directory):
    name = directory.name
    if not name.startswith(UNBOUND_SKILL_PREFIX):
        return None
    slug = name[len(UNBOUND_SKILL_PREFIX):]
    return slug if _skill_policy_valid_slug(slug) else None


def installed_skill_report():
    report = []
    for directory in _managed_skill_dirs():
        slug = _managed_skill_slug(directory)
        if not slug:
            continue
        skill_file = directory / 'SKILL.md'
        if skill_file.is_symlink():
            continue
        try:
            digest = hashlib.sha256(skill_file.read_bytes()).hexdigest()
        except OSError:
            continue
        report.append({'slug': slug, 'sha256': digest})
    return report


def _managed_skill_state(slug):
    directory = MANAGED_SKILLS_ROOT / (UNBOUND_SKILL_PREFIX + slug)
    state = {'path': directory, 'exists': False, 'managed': False, 'sha256': None}
    try:
        state['exists'] = directory.is_dir()
        if state['exists']:
            marker = directory / UNBOUND_SKILL_MARKER
            skill_file = directory / 'SKILL.md'
            state['managed'] = (
                not directory.is_symlink()
                and marker.is_file()
                and not marker.is_symlink()
                and not skill_file.is_symlink()
            )
            if state['managed']:
                state['sha256'] = hashlib.sha256(skill_file.read_bytes()).hexdigest()
    except Exception:
        pass
    return state


def _valid_skill_entry(entry):
    if not isinstance(entry, dict):
        return False
    slug = entry.get('slug')
    content = entry.get('content')
    if not _skill_policy_valid_slug(slug) or not isinstance(content, str) or not content:
        return False
    data = content.encode('utf-8')
    if len(data) > 1024 * 1024:
        return False
    wire_hash = entry.get('sha256')
    if (
        not isinstance(wire_hash, str)
        or not re.fullmatch(r'[0-9a-f]{64}', wire_hash)
        or wire_hash != hashlib.sha256(data).hexdigest()
    ):
        return False
    state = _managed_skill_state(slug)
    return not state['exists'] or state['managed']


def _valid_skill_plan(plan):
    if not isinstance(plan, dict):
        return False
    installs = plan.get('install', [])
    removals = plan.get('remove', [])
    if not isinstance(installs, list) or not isinstance(removals, list):
        return False
    install_slugs = []
    for entry in installs:
        if not _valid_skill_entry(entry):
            return False
        install_slugs.append(entry['slug'])
    if len(install_slugs) != len(set(install_slugs)):
        return False
    if any(not _skill_policy_valid_slug(slug) for slug in removals):
        return False
    if len(removals) != len(set(removals)):
        return False
    return not set(install_slugs).intersection(removals)


def install_injected_skills(inject_skills):
    succeeded = True
    try:
        entries = inject_skills if isinstance(inject_skills, list) else []
        for entry in entries:
            slug = entry.get('slug') if isinstance(entry, dict) else None
            try:
                content = entry.get('content') if isinstance(entry, dict) else None
                if not _skill_policy_valid_slug(slug):
                    log_error(f"skill injection rejected slug: {str(slug)[:64]!r}", 'skill_injection')
                    succeeded = False
                    continue
                if not isinstance(content, str) or not content:
                    log_error(f"skill injection rejected empty content for slug: {slug}", 'skill_injection')
                    succeeded = False
                    continue
                data = content.encode('utf-8')
                if len(data) > 1024 * 1024:
                    log_error(f"skill injection rejected oversized content for slug: {slug}", 'skill_injection')
                    succeeded = False
                    continue
                expected = hashlib.sha256(data).hexdigest()
                wire_hash = entry.get('sha256')
                if (
                    not isinstance(wire_hash, str)
                    or not re.fullmatch(r'[0-9a-f]{64}', wire_hash)
                    or wire_hash != expected
                ):
                    log_error(f"skill injection hash mismatch for {slug}", 'skill_injection')
                    succeeded = False
                    continue

                state = _managed_skill_state(slug)
                directory = state['path']
                if state['exists'] and not state['managed']:
                    log_error(f"skill dir not unbound-managed, skipping install: {directory}", 'skill_injection')
                    succeeded = False
                    continue
                if state['managed'] and state['sha256'] == expected:
                    continue

                created = not state['exists']
                directory.mkdir(parents=True, exist_ok=True)
                if created:
                    try:
                        marker_fd = os.open(
                            str(directory / UNBOUND_SKILL_MARKER),
                            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                            0o600,
                        )
                        os.close(marker_fd)
                    except OSError:
                        try:
                            directory.rmdir()
                        except OSError:
                            pass
                        raise

                fd, temp_path = tempfile.mkstemp(dir=str(directory), prefix='.SKILL.', suffix='.tmp')
                try:
                    with os.fdopen(fd, 'wb') as temp_file:
                        temp_file.write(data)
                    os.replace(temp_path, str(directory / 'SKILL.md'))
                except Exception:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                    raise
            except Exception as exc:
                log_error(f"skill injection failed for {str(slug)[:64]}: {exc}", 'skill_injection')
                succeeded = False
    except Exception as exc:
        log_error(f"skill injection failed: {exc}", 'skill_injection')
        succeeded = False
    return succeeded


def prune_injected_skills(remove_skills):
    try:
        entries = remove_skills if isinstance(remove_skills, list) else []
        for slug in entries:
            try:
                if not _skill_policy_valid_slug(slug):
                    log_error(f"skill prune rejected slug: {str(slug)[:64]!r}", 'skill_injection')
                    continue
                directory = MANAGED_SKILLS_ROOT / (UNBOUND_SKILL_PREFIX + slug)
                if not directory.is_dir():
                    continue
                marker = directory / UNBOUND_SKILL_MARKER
                if directory.is_symlink() or not marker.is_file() or marker.is_symlink():
                    log_error(f"skill dir not unbound-managed, skipping prune: {directory}", 'skill_injection')
                    continue
                shutil.rmtree(directory)
            except Exception as exc:
                log_error(f"skill prune failed for {str(slug)[:64]}: {exc}", 'skill_injection')
    except Exception as exc:
        log_error(f"skill prune failed: {exc}", 'skill_injection')


def _skills_lock_acquire():
    try:
        SKILLS_SYNC_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            return os.open(str(SKILLS_SYNC_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                age = time.time() - SKILLS_SYNC_LOCK_PATH.stat().st_mtime
            except OSError:
                age = SKILLS_SYNC_STALE_LOCK_SECONDS + 1
            if age < SKILLS_SYNC_STALE_LOCK_SECONDS:
                return None
            try:
                SKILLS_SYNC_LOCK_PATH.unlink()
                return os.open(str(SKILLS_SYNC_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except OSError:
                return None
    except OSError:
        return None


def _skills_lock_release(lock_fd):
    if lock_fd is None:
        return
    try:
        os.close(lock_fd)
    except OSError:
        pass
    try:
        SKILLS_SYNC_LOCK_PATH.unlink()
    except OSError:
        pass


class _SkillSyncNoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _request_skill_sync(api_key, payload):
    request = urllib.request.Request(
        f'{UNBOUND_GATEWAY_URL}/v1/hooks/skills/sync',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    opener = urllib.request.build_opener(_SkillSyncNoRedirects())
    try:
        with opener.open(request, timeout=SKILLS_SYNC_TIMEOUT_SECONDS) as response:
            body = response.read(4 * 1024 * 1024 + 1)
    except Exception as exc:
        log_error(f'skills sync request failed: {type(exc).__name__}', 'skill_injection')
        return None
    if not body or len(body) > 4 * 1024 * 1024:
        return None
    try:
        plan = json.loads(body.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return plan if isinstance(plan, dict) else None


def _sync_skills_once(api_key):
    lock_fd = _skills_lock_acquire()
    if lock_fd is None:
        return
    try:
        plan = _request_skill_sync(api_key, {'installed': installed_skill_report()})
        if plan is None:
            return
        if not _valid_skill_plan(plan):
            log_error('skills sync rejected invalid plan', 'skill_injection')
            return
        if not install_injected_skills(plan.get('install', [])):
            return
        prune_injected_skills(plan.get('remove', []))
    except Exception as exc:
        log_error(f'skills sync failed: {type(exc).__name__}', 'skill_injection')
    finally:
        _skills_lock_release(lock_fd)


def _dispatch_skills_sync(api_key):
    try:
        if not api_key:
            return
        if RUNNING_FROZEN:
            command = [sys.executable, 'sync-skills', SKILL_POLICY_TOOL]
        else:
            script = os.path.abspath(__file__)
            if not os.path.isfile(script):
                return
            command = [sys.executable, script, '--sync-skills']
        kwargs = {
            'stdin': subprocess.DEVNULL,
            'stdout': subprocess.DEVNULL,
            'stderr': subprocess.DEVNULL,
            'close_fds': True,
            'env': {**os.environ, SKILL_POLICY_API_KEY_ENV: api_key},
        }
        if os.name == 'nt':
            kwargs['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs['start_new_session'] = True
        subprocess.Popen(command, **kwargs)
    except Exception as exc:
        log_error(f"skills sync dispatch failed: {exc}", 'skill_injection')


def _attach_installed_skill_facts(metadata, event=None):
    installed = installed_skill_report()
    if not installed:
        return
    metadata['installed_skills'] = installed
    try:
        facts = _skill_policy_loaded_facts(event or {})
        if facts['loaded']:
            metadata['loaded_skills'] = sorted(facts['loaded'])
        metadata['skills_loaded_this_session'] = facts['session_count']
    except Exception as exc:
        log_error(f"skill loaded facts failed: {exc}", 'skill_injection')
    try:
        key = _skill_policy_turn_key(event or {})
        if key and _skill_turn_claim_path(key).exists():
            metadata['already_injected_this_turn'] = True
    except OSError:
        pass


def _skill_turn_claim_path(key):
    digest = hashlib.sha256(str(key).encode('utf-8', 'replace')).hexdigest()
    return SKILL_POLICY_STATE_ROOT / 'turn-claims' / digest


def _cleanup_skill_policy_state():
    cutoff = time.time() - 7 * 24 * 3600
    try:
        if not SKILL_POLICY_STATE_ROOT.is_dir():
            return
        for directory in SKILL_POLICY_STATE_ROOT.iterdir():
            if not directory.is_dir() or directory.is_symlink():
                continue
            # Budget per directory: one busy directory must not consume the whole
            # sweep and leave every later one uncollected.
            checked = 0
            for entry in directory.iterdir():
                checked += 1
                if checked > 1000:
                    break
                try:
                    if entry.is_file() and entry.stat().st_mtime < cutoff:
                        entry.unlink()
                except OSError:
                    continue
    except OSError:
        pass


def _claim_skill_injection_turn(event):
    try:
        key = _skill_policy_turn_key(event or {})
        if not key:
            return
        path = _skill_turn_claim_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return
        os.close(fd)
    except OSError:
        pass


def _apply_skill_lifecycle_actions(api_response, api_key):
    if not isinstance(api_response, dict):
        return
    try:
        if api_response.get('remove_skills'):
            lock_fd = _skills_lock_acquire()
            if lock_fd is not None:
                try:
                    prune_injected_skills(api_response.get('remove_skills'))
                finally:
                    _skills_lock_release(lock_fd)
        if api_response.get('sync_skills'):
            _dispatch_skills_sync(api_key)
    except Exception as exc:
        log_error(f"skill lifecycle action failed: {exc}", 'skill_injection')


def _skill_policy_turn_key(event):
    conversation = event.get('conversation_id')
    generation = event.get('generation_id')
    return f'{conversation}:{generation}' if conversation and generation else ''


def _skill_policy_loaded_facts(event):
    current = set()
    if event.get('hook_event_name') == 'beforeReadFile':
        name = _skill_name_from_path(event.get('file_path'), event.get('workspace_roots'))
        if isinstance(name, str) and name.startswith(UNBOUND_SKILL_PREFIX):
            slug = name[len(UNBOUND_SKILL_PREFIX):]
            if _skill_policy_valid_slug(slug):
                current.add(slug)

    transcript = event.get('transcript_path')
    if not isinstance(transcript, str) or not transcript:
        return {'loaded': current, 'session_count': len(current)}

    loaded = set(current)
    session_names = set(current)
    turns = 0
    in_window = True
    for raw in reversed(_skill_policy_transcript_tail(transcript)):
        try:
            entry = json.loads(raw)
        except Exception:
            continue
        if not isinstance(entry, dict):
            continue
        if entry.get('role') == 'user':
            turns += 1
            if turns > SKILL_LOADED_WINDOW:
                in_window = False
            continue
        if entry.get('role') != 'assistant':
            continue
        message = entry.get('message')
        content = message.get('content') if isinstance(message, dict) else None
        for part in content if isinstance(content, list) else []:
            if not isinstance(part, dict) or part.get('type') != 'tool_use' or part.get('name') != 'Read':
                continue
            tool_input = part.get('input')
            path = tool_input.get('path') if isinstance(tool_input, dict) else None
            name = _skill_name_from_path(path, event.get('workspace_roots'))
            if not isinstance(name, str) or not name.startswith(UNBOUND_SKILL_PREFIX):
                continue
            slug = name[len(UNBOUND_SKILL_PREFIX):]
            if not _skill_policy_valid_slug(slug):
                continue
            session_names.add(slug)
            if in_window:
                loaded.add(slug)
    try:
        with open(transcript, 'rb') as transcript_file:
            for raw in transcript_file:
                try:
                    entry = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(entry, dict) or entry.get('role') != 'assistant':
                    continue
                message = entry.get('message')
                content = message.get('content') if isinstance(message, dict) else None
                for part in content if isinstance(content, list) else []:
                    if not isinstance(part, dict) or part.get('type') != 'tool_use' or part.get('name') != 'Read':
                        continue
                    tool_input = part.get('input')
                    path = tool_input.get('path') if isinstance(tool_input, dict) else None
                    name = _skill_name_from_path(path, event.get('workspace_roots'))
                    if isinstance(name, str) and name.startswith(UNBOUND_SKILL_PREFIX):
                        slug = name[len(UNBOUND_SKILL_PREFIX):]
                        if _skill_policy_valid_slug(slug):
                            session_names.add(slug)
    except OSError:
        pass
    return {'loaded': loaded, 'session_count': len(session_names)}


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
            'hook_source': 'cursor',
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


def _gateway_unreachable_response():
    """Cursor deny shape for gateway-unreachable when failure mode is 'block'."""
    return {
        'permission': 'deny',
        'user_message': POLICY_CHECK_FAILURE_BLOCK_REASON,
        'agent_message': 'The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry.',
    }


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

def get_recent_user_prompts_for_session(conversation_id, n):
    if not conversation_id or n <= 0:
        return []

    logs = load_existing_logs()
    prompts = []
    for log in logs:
        event = log.get('event', {})
        if event.get('hook_event_name') != 'beforeSubmitPrompt':
            continue
        if event.get('conversation_id') != conversation_id:
            continue
        prompt = event.get('prompt')
        if prompt:
            prompts.append(prompt)
    return prompts[-n:]


def _build_user_prompt_payload(recent_user_prompts):
    last = recent_user_prompts[-1] if recent_user_prompts else None
    return {
        'messages': [{'role': 'user', 'content': last}] if last else [],
        'user_prompts': recent_user_prompts,
    }


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


def _set_approval_marker(command, policy_ids, application_id, request_id='', escalated_admin_contact=''):
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


def format_hook_response(api_response):
    """Convert API response to Cursor hook output format (permission/user_message/agent_message)."""
    if not api_response:
        return {}
    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')
    # On 'allow', emit no permission so Cursor uses its normal flow instead of the hook force-approving (keep any advisory context).
    if decision not in ('deny', 'block'):
        return {'agent_message': additional_context} if additional_context else {}
    response = {'permission': 'deny'}
    if reason:
        response['user_message'] = reason
    if additional_context:
        response['agent_message'] = additional_context
    return response

def _email_domain(email):
    try:
        if email and '@' in email:
            domain = email.rsplit('@', 1)[1].strip().lower()
            return domain or None
    except Exception:
        pass
    return None


def _cursor_state_db_path():
    if sys.platform == 'darwin':
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    if os.name == 'nt':
        appdata = os.environ.get('APPDATA')
        if not appdata:
            return None
        return Path(appdata) / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    return Path.home() / ".config" / "Cursor" / "User" / "globalStorage" / "state.vscdb"


def _read_cursor_item_table(db_path, keys):
    if not keys:
        return {}
    values = {}
    conn = None
    try:
        uri = f"file:{quote(str(db_path))}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        placeholders = ','.join('?' for _ in keys)
        cursor = conn.execute(
            f"SELECT key, value FROM ItemTable WHERE key IN ({placeholders})", keys
        )
        for key, value in cursor.fetchall():
            values[key] = value
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return values


def read_account_identity():
    plan = None
    email = None
    try:
        db_path = _cursor_state_db_path()
        if db_path and db_path.exists():
            values = _read_cursor_item_table(
                db_path, ['cursorAuth/cachedEmail', 'cursorAuth/stripeMembershipType']
            )
            email = (values.get('cursorAuth/cachedEmail') or '').strip() or None
            plan = values.get('cursorAuth/stripeMembershipType') or None
    except Exception:
        pass
    return {
        'org_id': None,
        'plan': plan,
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


def _valid_serial(value):
    return bool(value) and value.strip().lower() not in _PLACEHOLDER_SERIALS


def _get_device_serial():
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


def _device_serial(probe=True):
    """Hardware serial, computed once and cached. Never raises and never blocks the
    hook. On the latency-critical pre-tool path callers pass probe=False to read the
    cache only (no subprocess); sessionStart and the end-of-turn exchange probe and
    persist. A missing / corrupt / unreadable cache falls back to a fresh probe (when
    allowed), an unwritable cache is ignored (the probed value is still returned), and
    an unavailable serial returns None so the caller proceeds without it. The cache is
    shared with the claude-code hook, so we merge and write atomically (no torn file)."""
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


def build_account_identity(event=None, probe=False):
    """Cursor reports user_email on every hook (common schema); read it off the event
    and add the cached device serial. probe defaults False so the latency-critical
    pre-tool path only reads the cache; the end-of-turn exchange passes probe=True.
    Never raises — on any failure the hook proceeds with whatever identity it has."""
    try:
        identity = read_account_identity()
        if not isinstance(identity, dict):
            identity = {}
    except Exception:
        identity = {}
    try:
        if isinstance(event, dict):
            email = (event.get('user_email') or '').strip() or None
            if email:
                identity['user_email'] = email
                if not identity.get('email_domain'):
                    identity['email_domain'] = _email_domain(email)
        serial = _device_serial(probe=probe)
        if serial:
            identity['device_serial'] = serial
    except Exception:
        pass
    return identity


# Cursor surfaces file ops through several event shapes; map each to a normalized
# operation so a pre event (preToolUse Write/Read/Delete) and its completion
# (afterFileEdit / beforeReadFile) for the same path hash to the same synthetic id.
_CURSOR_FILE_OP = {
    'Write': 'write', 'Edit': 'write', 'Delete': 'delete', 'Read': 'read',
    'afterFileEdit': 'write', 'beforeReadFile': 'read',
}


def _resolve_tool_use_id(event):
    """Stable per-call id: the native tool_use_id when Cursor supplies one, else a
    deterministic synthetic id. The key uses ONLY fields byte-identical across the
    before* (pre) and after* (completion) event for the same call — conversation_id,
    generation_id, raw tool_name, and canonical content — so pre and post compute the
    same id. MCP after* events drop the server 'command', so MCP is keyed on
    tool_input only. Fail-open: never raises, falls back to native-or-None."""
    try:
        if not isinstance(event, dict):
            return None
        native = event.get('tool_use_id')
        if native:
            return native
        hook_name = event.get('hook_event_name') or ''
        tool_name = event.get('tool_name') or ''
        ti = event.get('tool_input') if isinstance(event.get('tool_input'), dict) else {}
        # File ops arrive in several shapes (preToolUse Write/Read/Delete, afterFileEdit,
        # beforeReadFile). Normalize them to (operation, path) so a pre event and its
        # completion for the SAME file hash to the same id -- the differing tool_name /
        # tool_input / edits shapes would otherwise fork the id.
        file_op = _CURSOR_FILE_OP.get(tool_name) or _CURSOR_FILE_OP.get(hook_name)
        file_path = event.get('file_path') or ti.get('file_path') or ti.get('path')
        if file_op and file_path:
            tool_disc, content = 'file', file_op + ':' + str(file_path)
        elif 'MCP' in hook_name:
            tool_disc, content = tool_name, json.dumps(ti, sort_keys=True)
        elif event.get('command') is not None:
            tool_disc, content = tool_name, str(event.get('command'))
        elif ti:
            tool_disc, content = tool_name, json.dumps(ti, sort_keys=True)
        else:
            tool_disc, content = tool_name, ''
        key = '\x1f'.join((
            str(event.get('conversation_id') or ''),
            str(event.get('generation_id') or ''),
            tool_disc,
            content,
        ))
        return 'unb-' + hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:24]
    except Exception:
        return event.get('tool_use_id') if isinstance(event, dict) else None


def process_pre_tool_use(event, api_key):
    """preToolUse entry point. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for file tools when no policy covers them."""
    gate = _repo_gate_evaluate(event, event.get('tool_name', ''))
    if gate:
        return _repo_gate_deny_response(gate['repo'])
    return _evaluate_pre_tool_use_policies(event, api_key)


def _evaluate_pre_tool_use_policies(event, api_key):
    """Run the gateway policy check for a preToolUse event."""
    tool_name = event.get('tool_name', '')

    if tool_name not in PRETOOL_NATIVE_TOOLS:
        return {}

    cache = load_policy_cache()
    tools_to_check = cache.get('tools_to_check', []) if cache else []
    need_pull_policies = cache is None or is_cache_stale(cache)

    if tool_name not in tools_to_check and not need_pull_policies:
        return {}

    generation_id = event.get('generation_id')
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'
    tool_input = event.get('tool_input') or {}

    recent_user_prompts = get_recent_user_prompts_for_session(
        conversation_id, PRETOOL_USER_MESSAGES_LIMIT
    )
    metadata = dict(event)
    _attach_installed_skill_facts(metadata, event)
    file_path = tool_input.get('file_path', '')
    if file_path:
        metadata['file_path'] = file_path

    approval_key = f"{tool_name}:{file_path}" if file_path else tool_name
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'tool_name': tool_name,
            'command': '',
            'metadata': metadata
        },
        'account_identity': build_account_identity(event),
        **_build_user_prompt_payload(recent_user_prompts),
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
                return {}
            elif result == 'deny':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This action was denied via Slack.',
                    'agent_message': 'This action was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                }
            else:
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_user_message = f'Blocked by organization policy. Approval request timed out — ask {admin_contact} to check Slack and retry.'
                else:
                    timeout_user_message = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry.'
                return {
                    'permission': 'deny',
                    'user_message': timeout_user_message,
                    'agent_message': 'This action was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                }

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return _gateway_unreachable_response()
        report_error_to_gateway(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={tool_name}',
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
        admin_contact = approval_check.get('escalatedAdminContact', '') or ''

        if admin_contact:
            user_message = (
                f'We could not find your Slack account, so an approval request was sent to {admin_contact}. '
                'Please ask them to approve it in Slack.'
            )
        else:
            user_message = 'An approval request has been sent to your Slack DMs. Please approve it there.'

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact)
        return {
            'permission': 'deny',
            'user_message': user_message,
            'agent_message': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                f'Tell the user: "{user_message}" '
                'Then immediately retry the exact same tool call with the exact same arguments — '
                'do not modify them in any way, do not add sleep or any prefix. '
                'Retry exactly once — the second attempt will wait for the approval.'
            ),
        }

    if (
        api_response.get('decision') == 'deny'
        and api_response.get('inject_skills')
        and api_response.get('additionalContext')
    ):
        _claim_skill_injection_turn(event)
    _apply_skill_lifecycle_actions(api_response, api_key)
    return format_hook_response(api_response)


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


# KEEP IN SYNC: coding-discovery-tool mcp_tools_cache.py + all 5 hook copies — byte-identical, do not diverge.
# Fingerprints key the local tool-hash cache; Redis tool scores are separately
# keyed by tool content hash. Keep fingerprint output aligned with data/gateway.

_MCP_TOOLS_CACHE_FILENAME = 'mcp-tools-cache.json'
_MCP_TOOLS_CACHE_MAX_BYTES = 2 * 1024 * 1024
_MCP_CACHE_CODING_TOOL_NAMES = frozenset({'cursor', 'cursor cli'})
_MCP_CACHE_CODING_TOOL_PREFIXES = ()
_UNBOUND_CODING_TOOL = 'Cursor'


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


def _read_mcp_server_config(server_name, config_path):
    """
    Read an MCP server's config (url, command, args) from a config file.
    Returns a dict with only the fields needed for fingerprinting, or None.
    Never includes env or headers (secrets).
    """
    try:
        if not config_path.exists():
            return None
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.loads(f.read())
        servers = config.get('mcpServers', {})
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


def process_pre_tool_use_execution(event, api_key, tool_name, command, mcp_server=None, mcp_tool=None):
    """beforeShellExecution / beforeMCPExecution entry point; the gate runs first and applies to the shell event only, an MCP call names no local path to resolve."""
    gate = _repo_gate_evaluate(event, tool_name, command)
    if gate:
        return _repo_gate_deny_response(gate['repo'])
    return _evaluate_pre_tool_use_execution_policies(
        event, api_key, tool_name, command, mcp_server=mcp_server, mcp_tool=mcp_tool)


def _evaluate_pre_tool_use_execution_policies(event, api_key, tool_name, command, mcp_server=None, mcp_tool=None):
    """Run the gateway policy check for a shell/MCP execution event."""
    generation_id = event.get('generation_id')
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    recent_user_prompts = get_recent_user_prompts_for_session(
        conversation_id, PRETOOL_USER_MESSAGES_LIMIT
    )

    # Build metadata with the raw event, inject mcp fields if present
    metadata = dict(event)
    _attach_installed_skill_facts(metadata, event)
    if mcp_server is not None:
        metadata['mcp_server'] = mcp_server

        server_cfg = _read_mcp_server_config(mcp_server, CURSOR_MCP_CONFIG_PATH)
        if server_cfg:
            metadata['mcp_server_config'] = _augment_script_hash(server_cfg, metadata.get('cwd'))

    if mcp_tool is not None:
        metadata['mcp_tool'] = mcp_tool

    _attach_tool_content_hash(metadata)

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

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
        'account_identity': build_account_identity(event),
        **_build_user_prompt_payload(recent_user_prompts),
    }

    _tuid = _resolve_tool_use_id(event)
    if _tuid:
        request_body['pre_tool_use_data']['tool_use_id'] = _tuid

    if not is_retry:
        request_body['first_approval_check'] = True

    # On retry, skip the gateway call — use cached IDs from the marker and poll.
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
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This command was denied via Slack.',
                    'agent_message': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                }
            else:
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_user_message = f'Blocked by organization policy. Approval request timed out — ask {admin_contact} to check Slack and retry the command.'
                else:
                    timeout_user_message = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.'
                return {
                    'permission': 'deny',
                    'user_message': timeout_user_message,
                    'agent_message': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                }

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return _gateway_unreachable_response()
        report_error_to_gateway(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={tool_name}',
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
        admin_contact = approval_check.get('escalatedAdminContact', '') or ''

        if admin_contact:
            user_message = (
                f'We could not find your Slack account, so an approval request was sent to {admin_contact}. '
                'Please ask them to approve it in Slack.'
            )
        else:
            user_message = 'An approval request has been sent to your Slack DMs. Please approve it there.'

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact)
        return {
            'permission': 'deny',
            'user_message': user_message,
            'agent_message': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                f'Tell the user: "{user_message}" '
                'Then immediately retry the exact same tool call with the exact same command — '
                'do not modify the command in any way, do not add sleep or any prefix. '
                'Retry exactly once — the second attempt will wait for the approval.'
            ),
        }

    
    if mcp_server is not None and api_response.get('unknown_mcp_server'):
        server_cfg = metadata.get('mcp_server_config')
        if server_cfg:
            _dispatch_mcp_server_scan(mcp_server, server_cfg)

    if (
        api_response.get('decision') == 'deny'
        and api_response.get('inject_skills')
        and api_response.get('additionalContext')
    ):
        _claim_skill_injection_turn(event)
    _apply_skill_lifecycle_actions(api_response, api_key)
    return format_hook_response(api_response)


def process_user_prompt_submit(event, api_key):
    """Process beforeSubmitPrompt event for policy checking. Also refreshes the policy cache, which is what makes the session's FIRST gated tool call enforceable: the gate never calls the network."""
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    metadata = {}
    cwd = event.get('cwd')
    if not isinstance(cwd, str) or not cwd:
        roots = event.get('workspace_roots')
        cwd = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else None
    if cwd:
        metadata['cwd'] = cwd
    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(event),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else [],
        'pre_tool_use_data': {'tool_name': '', 'command': '', 'metadata': metadata},
    }
    _attach_installed_skill_facts(request_body['pre_tool_use_data']['metadata'], event)
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    _apply_skill_lifecycle_actions(api_response, api_key)
    if isinstance(api_response, dict) and api_response.get('decision') not in ('deny', 'block'):
        context = api_response.get('additionalContext', '')
        if api_response.get('inject_skills') and isinstance(context, str) and context.strip():
            _defer_prompt_skill_context(event, context, api_response.get('user_notice'))
    return api_response if api_response else {}


def _deferred_skill_context_path(event):
    identity = '\x1f'.join((
        str(event.get('conversation_id') or ''),
        str(event.get('generation_id') or ''),
    ))
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return SKILL_POLICY_STATE_ROOT / 'pending' / digest


def _defer_prompt_skill_context(event, context, notice=None):
    try:
        if not isinstance(context, str) or not context.strip():
            return
        target = _deferred_skill_context_path(event)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {'context': context.strip()}
        if isinstance(notice, str) and notice.strip():
            payload['notice'] = notice.strip()
        fd, temp_path = tempfile.mkstemp(dir=str(target.parent), prefix='.pending-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
                json.dump(payload, temp_file)
            os.replace(temp_path, target)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
    except Exception as exc:
        log_error(f"skill context defer failed: {exc}", 'skill_injection')


def _consume_deferred_skill_context(event):
    target = _deferred_skill_context_path(event)
    claim = target.with_name(f'{target.name}.claim-{os.getpid()}')
    try:
        os.replace(target, claim)
    except OSError:
        return '', ''
    try:
        raw = claim.read_text(encoding='utf-8').strip()
    except OSError:
        return '', ''
    finally:
        try:
            claim.unlink()
        except OSError:
            pass
    try:
        stored = json.loads(raw)
    except Exception:
        # Pre-JSON pending files held the bare context and carried no notice.
        return raw, ''
    if not isinstance(stored, dict):
        return '', ''
    context = stored.get('context')
    notice = stored.get('notice')
    return (context if isinstance(context, str) else ''), (notice if isinstance(notice, str) else '')


def _with_deferred_skill_context(event, response):
    if not isinstance(response, dict) or response.get('permission') == 'deny':
        return response
    context, notice = _consume_deferred_skill_context(event)
    if not context:
        return response
    existing = response.get('agent_message')
    agent_message = existing if existing == context else '\n\n'.join(
        part for part in (existing, context) if isinstance(part, str) and part.strip()
    )
    _claim_skill_injection_turn(event)
    # Cursor only feeds agent_message to the model on a denied tool call.
    # Deny this first call once, then the agent invokes the skill and retries.
    return {
        **response,
        'permission': 'deny',
        'user_message': notice or 'Loading a skill required by organization policy. The agent will retry this action.',
        'agent_message': agent_message,
    }


def _cursor_usage_from_event(event):
    """Map Cursor stop/afterAgentResponse token fields to the gateway usage shape."""
    if not isinstance(event, dict):
        return None
    if not any(k in event for k in ('input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens')):
        return None

    def _i(key):
        try:
            return max(int(event.get(key) or 0), 0)
        except (TypeError, ValueError):
            return 0

    input_tokens = _i('input_tokens')
    output_tokens = _i('output_tokens')
    cache_read = _i('cache_read_tokens')
    cache_write = _i('cache_write_tokens')
    base_input = max(input_tokens - cache_read, 0)

    if not (base_input or output_tokens or cache_read or cache_write):
        return None

    return {
        'input_tokens': base_input,
        'output_tokens': output_tokens,
        'cache_read_input_tokens': cache_read,
        'cache_creation_input_tokens': cache_write,
        'total_tokens': base_input + output_tokens + cache_read + cache_write,
    }


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
    # Repo/org names can contain spaces (e.g. Azure DevOps); the URL path
    # arrives percent-encoded, so decode before splitting into org/repo.
    path = unquote(path)
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


# `cd <target>` occurrences — absolute, ~-rooted, or relative.
_CD_TARGET_RE = re.compile(r'(?:^|[;&|\n]\s*|\bthen\s+|\bdo\s+)cd\s+(["\']?)([^\s"\';|&]+)\1')


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


# --- Repository-scope gate: blocks writes, git commands and shell writes in repos outside the org's allowed scope; Cursor consults it from both preToolUse and beforeShellExecution ---

# Write tools, git commands and shell writes only; reads, conversation and every other shell command (ls, cat, npm test) are ungated.
_REPO_GATE_SHELL_TOOL = 'Shell'
_REPO_GATE_SHELL_TOOLS = frozenset({_REPO_GATE_SHELL_TOOL})
_REPO_GATE_WRITE_TOOLS = frozenset({'Write', 'Delete'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)






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


def _repo_gate_workspace_dir(event):
    """The event's cwd when Cursor sends one, else the first workspace root."""
    cwd = event.get('cwd')
    if isinstance(cwd, str) and cwd:
        return cwd
    roots = event.get('workspace_roots')
    if isinstance(roots, list) and roots and isinstance(roots[0], str):
        return roots[0]
    return None


def _repo_gate_candidates(event, tool_name, command):
    """Paths a Cursor call works in, backstopped by the workspace root."""
    if tool_name == _REPO_GATE_SHELL_TOOL:
        candidates = []
        if isinstance(command, str) and command:
            candidates.extend(
                p for p in _ABS_PATH_RE.findall(command)
                if not _is_system_checkout_path(p)
            )
            candidates.extend(
                _git_path_opt_targets(command, _repo_gate_workspace_dir(event))
            )
        if not candidates:
            workspace = _repo_gate_workspace_dir(event)
            if workspace:
                candidates.append(workspace)
        return candidates
    tool_input = event.get('tool_input') or {}
    path = (event.get('file_path') or tool_input.get('file_path')
            or tool_input.get('path'))
    if not isinstance(path, str) or not path:
        return []
    # A relative path resolves against the workspace dir, or nothing is judged.
    if not path.startswith('/'):
        workspace = _repo_gate_workspace_dir(event)
        if workspace:
            path = os.path.normpath(os.path.join(workspace, path))
    if path.startswith('/') and not _is_system_checkout_path(path):
        return [os.path.dirname(path)]
    return []


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


def _repo_gate_evaluate(event, tool_name, command=''):
    """Verdict for one tool call: None allows, else deny. Never raises."""
    try:
        if not _repo_gate_applies(tool_name, command):
            return None
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None

        candidates = _repo_gate_candidates(event, tool_name, command)
        repo = _repo_gate_violating_repo(candidates, block_policies, {})
        gate = {'decision': 'deny', 'repo': repo} if repo else None
        _repo_gate_report(gate, block_policies, {
            'app_label': 'cursor',
            'session_id': event.get('conversation_id'),
            'tool_name': tool_name,
            # The shell event carries its command as an argument; file events name their path on the event itself.
            'tool_input': command or event.get('tool_input') or event,
        })
        return gate
    except Exception:
        return None


def _repo_gate_deny_response(repo):
    return format_hook_response({
        'decision': 'deny',
        'reason': _repo_gate_block_reason(repo),
        'additionalContext': REPO_GATE_BLOCK_CONTEXT,
    })


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


def _cursor_user_query(text):
    """The typed text of a Cursor transcript user entry. Cursor wraps it in <user_query>
    alongside a <timestamp> preamble; anything unwrapped is returned as-is."""
    if not isinstance(text, str):
        return ''
    start = text.find('<user_query>')
    if start == -1:
        return text.strip()
    # Close on the LAST tag, not the first: the prompt itself may contain the literal
    # token, and cutting at an interior one would drop everything the user typed after it.
    end = text.rfind('</user_query>')
    if end <= start:
        return text[start + len('<user_query>'):].strip()
    return text[start + len('<user_query>'):end].strip()


def _cursor_turn_prompts(transcript_path):
    """Every prompt the current turn carries, from Cursor's own transcript. A prompt typed
    while the agent is working joins the running generation without firing
    beforeSubmitPrompt, so the hook events alone see only the first one."""
    if not transcript_path or not os.path.exists(transcript_path):
        return []
    current, completed = [], []
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if entry.get('type') == 'turn_ended':
                    completed = current
                    current = []
                    continue
                if entry.get('role') != 'user':
                    continue
                content = (entry.get('message') or {}).get('content')
                blocks = content if isinstance(content, list) else []
                for block in blocks:
                    if not isinstance(block, dict) or block.get('type') != 'text':
                        continue
                    typed = _cursor_user_query(block.get('text'))
                    if typed:
                        current.append(typed)
    except OSError:
        return []
    return current or completed


def build_llm_exchange(events, api_key=None):
    """Build standard LLM exchange format from events."""
    messages = []
    assistant_tool_uses = []
    
    user_prompts = []
    transcript_path = None
    assistant_response = None
    conversation_id = None
    generation_id = None
    model = None
    user_email = None
    request_initialized = None
    request_completed = None
    usage = None
    # Working-dir context for per-entry project attribution: every Cursor
    # event carries workspace_roots; shell events carry an explicit cwd.
    workspace_cwd = None
    workspace_roots = []
    read_skills = set()
    root_projects = {}

    for log_entry in events:
        event = log_entry.get('event', {})
        hook_event_name = event.get('hook_event_name')

        if not workspace_cwd:
            roots = event.get('workspace_roots')
            if isinstance(roots, list) and roots and isinstance(roots[0], str):
                workspace_cwd = roots[0]
                workspace_roots = list(roots)

        if not conversation_id:
            conversation_id = event.get('conversation_id')

        if not generation_id:
            generation_id = event.get('generation_id')

        if not model:
            model = event.get('model')

        if not user_email:
            user_email = event.get('user_email')

        if hook_event_name == 'beforeSubmitPrompt':
            # A generation can carry more than one prompt when the user types while Cursor is
            # still working. Anchor on the first; keeping the last would start the turn after
            # work the earlier prompt had already caused.
            prompt = event.get('prompt')
            if prompt:
                user_prompts.append(prompt)
            if request_initialized is None:
                request_initialized = log_entry.get('timestamp')

        elif hook_event_name == 'stop':
            request_completed = log_entry.get('timestamp')
            usage = _cursor_usage_from_event(event) or usage
            transcript_path = event.get('transcript_path') or transcript_path

        elif hook_event_name == 'beforeReadFile':
            file_path = event.get('file_path')
            read_entry = {
                'type': hook_event_name,
                'file_path': file_path,
                'content': event.get('content', ''),
                'attachments': event.get('attachments', []),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(
                    [os.path.dirname(file_path)]
                    if isinstance(file_path, str) and file_path.startswith('/') and not _is_system_checkout_path(file_path)
                    else [],
                    root_projects)
            }
            # Cursor loads a skill by reading its SKILL.md, so this read is the
            # only skill-invocation signal it emits.
            # Prefer the read event's own roots: the first logged event may
            # have carried an incomplete list.
            event_roots = [r for r in (event.get('workspace_roots') or [])
                           if isinstance(r, str) and r]
            skill_name = _skill_name_from_path(
                file_path,
                (event_roots + workspace_roots) or workspace_cwd)
            # Re-reading one SKILL.md in a turn is still a single invocation.
            # Keyed by path, not name: two skills can share a name under
            # different roots and are different skills.
            if skill_name and _skill_path_key(file_path) not in read_skills:
                read_skills.add(_skill_path_key(file_path))
                read_entry['skill_name'] = skill_name
                read_entry['skill_path'] = file_path
            assistant_tool_uses.append(read_entry)

        elif hook_event_name == 'postToolUse':
            tool_name = event.get('tool_name', '')

            if tool_name not in EXCHANGE_NATIVE_TOOLS:
                continue

            tool_output = event.get('tool_output', '')

            # Attribute the call to the repo it worked in: the event's own
            # cwd when present, else absolute paths inside tool_input.
            candidates = []
            if isinstance(event.get('cwd'), str):
                candidates.append(event['cwd'])
            tool_input = event.get('tool_input')
            if isinstance(tool_input, dict):
                for value in tool_input.values():
                    if isinstance(value, str) and value.startswith('/') and not _is_system_checkout_path(value):
                        candidates.append(os.path.dirname(value))

            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_output': tool_output,
                'duration': event.get('duration'),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates or [workspace_cwd], root_projects)
            })

        elif hook_event_name == 'afterFileEdit':
            file_path = event.get('file_path')
            assistant_tool_uses.append({
                'type': hook_event_name,
                'file_path': file_path,
                'edits': event.get('edits', []),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(
                    [os.path.dirname(file_path)]
                    if isinstance(file_path, str) and file_path.startswith('/') and not _is_system_checkout_path(file_path)
                    else [],
                    root_projects)
            })

        elif hook_event_name == 'afterShellExecution':
            command = event.get('command')
            # The event's cwd is where the command actually ran; absolute
            # paths in the command and the workspace root are fallbacks.
            candidates = []
            if isinstance(event.get('cwd'), str):
                candidates.append(event['cwd'])
            if isinstance(command, str):
                candidates.extend(
                    p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p)
                )
                candidates.extend(
                    _git_path_opt_targets(command, event.get('cwd') or workspace_cwd)
                )
            if not candidates and workspace_cwd:
                candidates.append(workspace_cwd)
            assistant_tool_uses.append({
                'type': hook_event_name,
                'command': command,
                'output': event.get('output', ''),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates, root_projects)
            })

        elif hook_event_name == 'afterMCPExecution':
            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': event.get('tool_name'),
                'tool_input': event.get('tool_input'),
                'result_json': event.get('result_json'),
                'tool_use_id': _resolve_tool_use_id(event)
            })
        
        elif hook_event_name == 'afterAgentResponse':
            assistant_response = event.get('text')
            usage = _cursor_usage_from_event(event) or usage
    
    # Cursor's transcript carries every prompt of the turn, including one typed while the
    # agent was working; the hook events see only those that fired beforeSubmitPrompt. The
    # transcript is per conversation and may already hold a later turn, so it is trusted
    # only when it opens with the prompt this generation started from.
    transcript_prompts = _cursor_turn_prompts(transcript_path)
    if (user_prompts and len(transcript_prompts) > len(user_prompts)
            and transcript_prompts[:len(user_prompts)] == user_prompts):
        # Append only what the hook did not capture. The events are the trusted text, so
        # they are never rewritten by the transcript, only extended by it.
        user_prompts = user_prompts + transcript_prompts[len(user_prompts):]

    # One message, not one per prompt: the backend keeps only the last user message.
    user_prompt = '\n\n'.join(user_prompts)
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})
    
    if assistant_response:
        assistant_msg = {'role': 'assistant', 'content': assistant_response}
        if assistant_tool_uses:
            assistant_msg['tool_use'] = assistant_tool_uses
        messages.append(assistant_msg)
    
    if not messages:
        return None
    
    if not model or model == 'default' or model == 'unknown':
        model = 'auto'

    exchange = {
        'conversation_id': conversation_id,
        'model': model,
        'messages': messages,
        'cwd': workspace_cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the workspace repo.
        'project': _project_for_paths([workspace_cwd], root_projects),
        'account_identity': build_account_identity({'user_email': user_email}, probe=True)
    }

    # Omit when unknown; gateway falls back
    if request_initialized:
        exchange['requestInitialized'] = request_initialized
    if request_completed:
        exchange['requestCompleted'] = request_completed

    if usage:
        exchange['usage'] = usage

    # Exact per-turn id for deterministic idempotency (vs a content hash).
    if generation_id:
        exchange['turn_request_id'] = generation_id

    return exchange


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False
    
    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/cursor"
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

    if len(logs) <= AUDIT_LOG_TOTAL_LIMIT:
        return

    conversation_order = []
    seen_conversations = set()

    for log in logs:
        event = log.get('event', {})
        conv_id = event.get('conversation_id')
        if conv_id and conv_id not in seen_conversations:
            conversation_order.append(conv_id)
            seen_conversations.add(conv_id)

    if len(conversation_order) > 1:
        most_recent_conv_id = conversation_order[-1]
        kept_logs = [
            log for log in logs
            if log.get('event', {}).get('conversation_id') == most_recent_conv_id
        ]
        save_logs(kept_logs)
    elif len(logs) > AUDIT_LOG_TOTAL_LIMIT:
        save_logs(logs[-AUDIT_LOG_TOTAL_LIMIT:])


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
                exchange = build_llm_exchange(events, api_key)
                if exchange:
                    send_to_api(exchange, api_key)
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


def _dispatch_mcp_server_scan(server_name, server_config):
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
            api_key = _machine_env('UNBOUND_CURSOR_API_KEY')
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
                api_key = _machine_env('UNBOUND_CURSOR_API_KEY')
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


def main():
    """Main entry point - read from stdin and process events."""
    global _cached_api_key
    # Get API key (will be None if not set)
    api_key = get_api_key()
    _cached_api_key = api_key

    if len(sys.argv) > 1 and sys.argv[1] == '--sync-skills':
        _sync_skills_once(api_key)
        return
    
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

        # sessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "sessionStart":
            _cleanup_skill_policy_state()
            _device_serial()  # warm the (slow) serial probe + cache once per session
            _dispatch_discovery()
            _dispatch_skills_sync(api_key)
            print("{}")
            return
        generation_id = event.get('generation_id')
        conversation_id = event.get('conversation_id')

        if hook_event_name == 'preToolUse':
            response = _with_deferred_skill_context(event, process_pre_tool_use(event, api_key))
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeShellExecution / beforeMCPExecution - check policy before execution
        if hook_event_name == 'beforeShellExecution':
            response = _with_deferred_skill_context(
                event, process_pre_tool_use_execution(event, api_key, 'Shell', event.get('command', ''))
            )
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        if hook_event_name == 'beforeMCPExecution':
            mcp_server = event.get('command', '')
            mcp_tool_name = event.get('tool_name', '')

            response = _with_deferred_skill_context(event, process_pre_tool_use_execution(
                event, api_key, f'MCP:{mcp_tool_name}', json.dumps(event.get('tool_input') or {}),
                mcp_server=mcp_server, mcp_tool=mcp_tool_name
            ))
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeSubmitPrompt - check policy before processing
        if hook_event_name == 'beforeSubmitPrompt':
            # No repo gate here: conversation is never gated, but this call refreshes the policy cache so the session's first gated TOOL call is enforceable.
            response = process_user_prompt_submit(event, api_key)

            # If denied, log the event, transform response for Cursor format and exit
            if response.get('decision') == 'deny':
                append_to_audit_log({
                    'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
                    'event': event
                })
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
        print(f"Error: {redact_secrets(str(e), _cached_api_key)}", file=sys.stderr)
        print("{}")


if __name__ == '__main__':
    main()
