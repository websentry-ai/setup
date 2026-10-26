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
import shlex
import sqlite3
import shutil
import urllib.request
import platform
import uuid
from typing import Any, Dict, List, Optional, Tuple
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
CURSOR_DB_TIMEOUT_SECONDS = 2
# The cached account only covers a database we could not read, so it is bounded:
# stale beyond this and the hook reports no account instead.
ACCOUNT_CACHE_MAX_AGE_SECONDS = 12 * 3600
ACCOUNT_CACHE_REFRESH_SECONDS = 15 * 60

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


def _emit(text):
    """Write a hook response line to stdout, treating a closed reader pipe as
    a benign no-op. The host may close the read end (timeout, cancel, session
    end) before we flush — that is not a hook error."""
    try:
        print(text, flush=True)
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


def get_unbound_attribution_enabled():
    """Read the org's Unbound attribution setting from cache, defaulting to off. Ignores TTL."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return False
    return cache.get('unbound_attribution_enabled') is True


def _attribution_footer(trace_id=None):
    """Footer closing a block shown to the user; no ID when no gateway saw the decision."""
    if trace_id:
        return '\n\nEnforced by Unbound · Trace ID ' + trace_id
    return '\n\nEnforced by Unbound'


def get_repo_policies():
    """Repo-scope policies from cache, [] if absent; a stale cache still applies."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return []
    policies = cache.get('repo_policies')
    return policies if isinstance(policies, list) else []


def save_policy_cache(tools_to_check=None, policy_check_failure_action=None, repo_policies=None, unbound_attribution_enabled=None):
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
            'last_synced': datetime.utcnow().isoformat() + 'Z',
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
            'repo_policies': repo_policies,
            'unbound_attribution_enabled': unbound_attribution_enabled,
        }
        with open(POLICY_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cache))
    except (OSError, TypeError):
        pass


def _gateway_unreachable_response():
    """Cursor deny shape for gateway-unreachable when failure mode is 'block'."""
    footer = _attribution_footer() if get_unbound_attribution_enabled() else ''
    return {
        'permission': 'deny',
        'user_message': POLICY_CHECK_FAILURE_BLOCK_REASON + footer,
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
        or 'unbound_attribution_enabled' in api_response
    ):
        save_policy_cache(
            tools_to_check=api_response.get('tools_to_check'),
            policy_check_failure_action=api_response.get('policy_check_failure_action'),
            repo_policies=api_response.get('repo_policies'),
            unbound_attribution_enabled=api_response.get('unbound_attribution_enabled'),
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


def _set_approval_marker(command, policy_ids, application_id, request_id='', escalated_admin_contact='', unbound_trace_id=''):
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
    placeholders = ','.join('?' for _ in keys)
    sql = f"SELECT key, value FROM ItemTable WHERE key IN ({placeholders})"
    quoted = quote(str(db_path))
    # mode=ro first: an immutable open ignores the -wal file, so a value Cursor
    # wrote but has not checkpointed reads back as missing, and the account then
    # looks unidentified. immutable stays as the fallback for a db with no -shm.
    readable = False
    for uri in (f"file:{quoted}?mode=ro", f"file:{quoted}?mode=ro&immutable=1"):
        conn = None
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=CURSOR_DB_TIMEOUT_SECONDS)
            values = {key: value for key, value in conn.execute(sql, keys).fetchall()}
            readable = True
            if values:
                return values
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    # None means "could not read", {} means "read fine, no such rows". A signed
    # out user is the second, and must not be given the previous account.
    return {} if readable else None


def _cursor_team_id(raw):
    """The team id from Cursor's cached team record; None for a personal account.
    An unreadable record is logged, since it reads as personal otherwise."""
    if raw in (None, ''):
        return None
    try:
        team = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except Exception as e:
        log_error("cursor team record unparsable: %s" % type(e).__name__, 'config')
        return None
    if not isinstance(team, dict):
        log_error("cursor team record is %s, expected object" % type(team).__name__, 'config')
        return None
    team_id = team.get('teamId')
    return str(team_id) if team_id not in (None, '') else None


def read_account_identity():
    plan = None
    email = None
    org_id = None
    unreadable = False
    try:
        db_path = _cursor_state_db_path()
        if db_path and db_path.exists():
            values = _read_cursor_item_table(
                db_path,
                ['cursorAuth/cachedEmail', 'cursorAuth/stripeMembershipType',
                 'cursorAuth/cachedTeam'],
            )
            if values is None:
                unreadable = True
            else:
                email = (values.get('cursorAuth/cachedEmail') or '').strip() or None
                plan = values.get('cursorAuth/stripeMembershipType') or None
                org_id = _cursor_team_id(values.get('cursorAuth/cachedTeam'))
    except Exception:
        unreadable = True
    if email:
        _remember_account(email, plan, org_id)
    elif unreadable:
        # Only when the read itself failed. A database that reads fine and holds
        # no account means signed out, and reusing the last account there would
        # hand a signed-out or switched user the previous approval.
        email, plan, org_id = _cached_account(plan)
    else:
        _forget_account()
    return {
        'org_id': org_id,
        'plan': plan,
        'auth_mode': None,
        'user_email': email,
        # Always derived from the email actually reported: a domain kept from a
        # different account is the one field the gate matches on.
        'email_domain': _email_domain(email),
    }


def _cached_account(plan):
    """Last account this hook read successfully, if it is still fresh. The age
    bound keeps a machine that stops reporting from carrying an approval forever.
    Never raises."""
    try:
        loaded = json.loads(IDENTITY_CACHE_PATH.read_text(encoding='utf-8'))
    except Exception:
        return None, plan, None
    if not isinstance(loaded, dict):
        return None, plan, None
    account = loaded.get('cursor_account')
    if not isinstance(account, dict):
        return None, plan, None
    seen_at = account.get('seen_at')
    if not isinstance(seen_at, (int, float)):
        return None, plan, None
    if (time.time() - seen_at) > ACCOUNT_CACHE_MAX_AGE_SECONDS:
        return None, plan, None
    email = account.get('user_email')
    email = email.strip() if isinstance(email, str) else None
    # The team is the one read with this email, so it names the same tenant.
    org_id = account.get('org_id') if isinstance(account.get('org_id'), str) else None
    return (email or None), (plan or account.get('plan')), (org_id if email else None)


def _forget_account():
    """Drop the cached account on a clean read with nobody signed in."""
    try:
        loaded = json.loads(IDENTITY_CACHE_PATH.read_text(encoding='utf-8'))
    except Exception:
        return
    if not isinstance(loaded, dict) or 'cursor_account' not in loaded:
        return
    try:
        del loaded['cursor_account']
        IDENTITY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = IDENTITY_CACHE_PATH.parent / (".identity.%d.tmp" % os.getpid())
        tmp.write_text(json.dumps(loaded), encoding='utf-8')
        os.replace(str(tmp), str(IDENTITY_CACHE_PATH))
    except Exception:
        pass


def _remember_account(email, plan, org_id=None):
    """Merge into the cache the device serial already shares. Never raises."""
    try:
        data = {}
        try:
            loaded = json.loads(IDENTITY_CACHE_PATH.read_text(encoding='utf-8'))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
        current = data.get('cursor_account')
        if (isinstance(current, dict) and current.get('user_email') == email
                and current.get('plan') == plan and current.get('org_id') == org_id
                and isinstance(current.get('seen_at'), (int, float))
                and (time.time() - current['seen_at']) < ACCOUNT_CACHE_REFRESH_SECONDS):
            return
        data['cursor_account'] = {
            'user_email': email, 'plan': plan, 'org_id': org_id, 'seen_at': int(time.time()),
        }
        IDENTITY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = IDENTITY_CACHE_PATH.parent / (".identity.%d.tmp" % os.getpid())
        tmp.write_text(json.dumps(data), encoding='utf-8')
        os.replace(str(tmp), str(IDENTITY_CACHE_PATH))
    except Exception:
        pass


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
                # Plan and team read with another account are not this one's.
                if (identity.get('user_email') or '').lower() != email.lower():
                    identity['plan'] = identity['org_id'] = None
                # Recompute, never keep: a domain left over from another account
                # is the field the gate matches on.
                identity['user_email'] = email
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
        return _repo_gate_deny_response(gate['repo'], gate.get('trace_id'))
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
            unbound_trace_id = marker_data.get('unboundTraceId')
            footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return {}
            elif result == 'deny':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This action was denied via Slack.' + footer,
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
                    'user_message': timeout_user_message + footer,
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

        # The gateway logged this hold under a trace ID; the retry's local verdicts reuse it.
        unbound_trace_id = api_response.get('unbound_trace_id') or ''
        footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact, unbound_trace_id=unbound_trace_id)
        return {
            'permission': 'deny',
            'user_message': user_message + footer,
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


def _hook_runtime_entrypoint(runtime, args):
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


def _hook_candidate_script(command, args):
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


_HOOK_MAX_SCRIPT_BYTES = 256 * 1024


def _hook_script_path(command, args, cwd):
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


def _hook_read_script_bytes(path):
    """First _HOOK_MAX_SCRIPT_BYTES bytes of a regular file, else None."""
    flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(os.open(path, flags), 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        return f.read(_HOOK_MAX_SCRIPT_BYTES)


def _compute_script_hash(command, args, cwd):
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
        return _repo_gate_deny_response(gate['repo'], gate.get('trace_id'))
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
            unbound_trace_id = marker_data.get('unboundTraceId')
            footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return {}
            elif result == 'deny':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This command was denied via Slack.' + footer,
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
                    'user_message': timeout_user_message + footer,
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

        # The gateway logged this hold under a trace ID; the retry's local verdicts reuse it.
        unbound_trace_id = api_response.get('unbound_trace_id') or ''
        footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact, unbound_trace_id=unbound_trace_id)
        return {
            'permission': 'deny',
            'user_message': user_message + footer,
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


# --- Repository-scope gate: blocks writes, git write subcommands and shell writes in repos outside the org's allowed scope; Cursor consults it from both preToolUse and beforeShellExecution ---

# Write tools, git write subcommands and shell writes only; reads, conversation and every other shell command (ls, cat, npm test) are ungated.
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
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it runs a git write or writes a file."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_write_command(command) or _is_shell_write_command(command)
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


def _repo_gate_block_reason(repo, trace_id=None):
    reason = (
        'Blocked by organization policy. "%s" is outside your organization\'s '
        'allowed repository scope.' % repo
    )
    return reason + _attribution_footer(trace_id) if trace_id else reason


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
        if gate and get_unbound_attribution_enabled():
            gate['trace_id'] = str(uuid.uuid4())
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


def _repo_gate_deny_response(repo, trace_id=None):
    return format_hook_response({
        'decision': 'deny',
        'reason': _repo_gate_block_reason(repo, trace_id),
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
_TRANSFER_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990, 'ws': 80, 'wss': 443}
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
_TRANSFER_CURL_PROXIES = frozenset({'-x', '--proxy', '--preproxy', '--socks4', '--socks4a', '--socks5',
                                    '--socks5-hostname'})
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
    'followrellink', 'verbose', 'debug', 'whatif', 'confirm'})
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


def _transfer_proxied(env: Dict) -> bool:
    """Whether the command itself sets a proxy for curl, wget, HTTPie or PowerShell in their environment."""
    return any(env.get(key) for key in _TRANSFER_PROXY_ENV)


def _transfer_curl(args: List[str], proxied: bool = False) -> List[tuple]:
    """curl's URLs: sent to when their request uploads or sends data, else fetched from. Each --next starts a request,
    --resolve pins carry on, and globs reach every host unless --globoff; a rejected glob stops curl. Each carries
    whether it goes through a proxy, by option or by a proxy the command set."""
    endpoints, pins, i = [], [], 0
    while True:
        urls, sends, overrides, globoff, i, proxy = _transfer_curl_request(args, i)
        pins += [value for option, value in overrides if option == '--resolve']
        connects = [value for option, value in overrides if option == '--connect-to']
        for url in urls:
            expanded = [url] if globoff else _transfer_curl_glob(url)
            if expanded is None:
                return endpoints
            endpoints += [('out' if sends else 'in', _transfer_url_host(one, _TRANSFER_CURL_SCHEMES), None,
                           _transfer_curl_dial(one, connects, pins), proxied or proxy) for one in expanded]
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
    it turns globbing off, where the next request starts, whether it names a proxy); a --next that is an option's value
    does not end it."""
    urls, flags, method, overrides, proxy = [], set(), '', [], False
    while i < len(args):
        arg, value, i = args[i], None, i + 1
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
        elif arg in _TRANSFER_CURL_PROXIES and value is not None:
            proxy = bool(value)  # an empty one turns the proxy off
    sends = flags & _TRANSFER_CURL_UPLOADS or method in _TRANSFER_SENDING_METHODS or \
        (flags & _TRANSFER_CURL_BODIES and not flags & {'-G', '--get'})
    return urls, bool(sends), overrides, bool(flags & {'-g', '--globoff'}), i, proxy


def _transfer_wget(args: List[str], proxied: bool = False) -> List[tuple]:
    """wget's URLs: sent to when it posts data or a file; else fetched from. Each carries whether it goes through a
    proxy: one the command set or an -e proxy setting, unless --no-proxy or -e use_proxy=off turns proxies off."""
    urls, flags, settings, i = [], set(), {}, 0
    while i < len(args):
        arg, name, value, i = args[i], None, None, i + 1
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
    proxy = on and (proxied or 'useproxy' in settings or any(settings.get(k) for k in ('httpproxy', 'httpsproxy',
                                                                                       'ftpproxy')))
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
    """nc's host: sent to when its stdin is fed in; a listener reaches no host. ncat's --proxy, or OpenBSD nc's -x or
    -X, reaches it through a proxy."""
    positional, flags, i = [], set(), 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg.startswith('--'):
            if '=' not in arg and arg in _TRANSFER_NC_LONG_VALUES:
                i += 1
            flags.add(arg)
        elif arg.startswith('-') and len(arg) > 1:
            flag, _, i = _transfer_short_option(arg, args, i, _TRANSFER_NC_SHORT_VALUES, flags)
            flags.add(flag)
        else:
            positional.append(arg)
    if not positional or flags & {'-l', '--listen', '-U', '--unixsock'}:
        return []
    return [('out' if sends else '', positional[0], None, None, bool(flags & {'--proxy', '-x', '-X'}))]


def _transfer_socat(args: List[str], sends: bool) -> List[tuple]:
    """The hosts socat's two addresses connect to: sent to when its stdin is fed in. A host a PROXY or SOCKS address
    names, or one with a proxyport= or socksport= option, is reached through that proxy."""
    addresses, i = [], 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg in _TRANSFER_SOCAT_VALUE_OPTIONS:
            i += 1
        elif arg == '-' or not arg.startswith('-'):
            addresses.append(arg)
    endpoints = []
    for address in addresses[:2]:
        match = re.match(r'^(?:(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?|'
                         r'(proxy(?:-connect)?|socks4a?|socks5(?:-connect)?):[^:,]+):(\[[^\]]+\]|[^:,]+):', address,
                         re.IGNORECASE)
        if match:
            proxied = bool(match.group(1) or re.search(r',\s*(?:proxyport|socksport)=', address, re.IGNORECASE))
            endpoints.append(('out' if sends else '', match.group(2), None, None, proxied))
    return endpoints


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


def _transfer_web_cmdlet(args: List[str], sends: bool, proxied: bool = False) -> List[tuple]:
    """Invoke-WebRequest's or Invoke-RestMethod's URI: sent to with a body, file, form, piped input or sending
    method; else fetched from. It goes through a proxy with -Proxy, or one the command set unless -NoProxy."""
    uri, out, positional, proxy, i = '', sends, [], None, 0
    while i < len(args):
        arg, i = args[i], i + 1
        if not re.match(r'^-[A-Za-z]', arg):
            positional.append(arg)
            continue
        name, colon, value = arg[1:].partition(':')
        name = name.lower()
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
        raw = (_transfer_curl if tool == 'curl' else _transfer_wget)(args, _transfer_proxied(env))
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
    key = ('address', host)
    if key not in state:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            if not lookup:
                return 'unresolved'  # a call that may not have run is never looked up
            remaining = _transfer_deadline(state) - time.monotonic()
            addresses = _transfer_resolve(host, min(_TRANSFER_DNS_TIMEOUT, remaining)) if remaining > 0 else []
        state[key] = _transfer_address_kind(addresses)
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
        resolved = resolved or host
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
    transfer_state = {}

    for log_entry in events:
        event = log_entry.get('event', {})
        stamp = log_entry.get('timestamp')
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
            read_entry = _with_call_ts({
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
            }, stamp)
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
                read_entry['content_hash'] = _skill_content_hash(file_path)
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

            assistant_tool_uses.append(_with_call_ts({
                'type': hook_event_name,
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_output': tool_output,
                'duration': event.get('duration'),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates or [workspace_cwd], root_projects)
            }, stamp))

        elif hook_event_name == 'afterFileEdit':
            file_path = event.get('file_path')
            assistant_tool_uses.append(_with_call_ts({
                'type': hook_event_name,
                'file_path': file_path,
                'edits': event.get('edits', []),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(
                    [os.path.dirname(file_path)]
                    if isinstance(file_path, str) and file_path.startswith('/') and not _is_system_checkout_path(file_path)
                    else [],
                    root_projects)
            }, stamp))

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
            shell_entry = _with_call_ts({
                'type': hook_event_name,
                'command': command,
                'output': event.get('output', ''),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates, root_projects)
            }, stamp)
            # Cursor runs commands in PowerShell on Windows, where a ; inside an @{ } hashtable separates its entries.
            script = _transfer_hashtables_emptied(command) if os.name == 'nt' and isinstance(command, str) else command
            transfer = _transfer(script, event.get('cwd') or workspace_cwd, transfer_state)
            if transfer:
                shell_entry['transfer'] = transfer
            assistant_tool_uses.append(shell_entry)

        elif hook_event_name == 'afterMCPExecution':
            assistant_tool_uses.append(_with_call_ts({
                'type': hook_event_name,
                'tool_name': event.get('tool_name'),
                'tool_input': event.get('tool_input'),
                'result_json': event.get('result_json'),
                'tool_use_id': _resolve_tool_use_id(event)
            }, stamp))
        
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
            _emit("{}")
            return
        
        # Parse the event
        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            _emit("{}")
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
            _emit("{}")
            return
        generation_id = event.get('generation_id')
        conversation_id = event.get('conversation_id')

        if hook_event_name == 'preToolUse':
            response = _with_deferred_skill_context(event, process_pre_tool_use(event, api_key))
            _emit(json.dumps(response))
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeShellExecution / beforeMCPExecution - check policy before execution
        if hook_event_name == 'beforeShellExecution':
            response = _with_deferred_skill_context(
                event, process_pre_tool_use_execution(event, api_key, 'Shell', event.get('command', ''))
            )
            _emit(json.dumps(response))
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
            _emit(json.dumps(response))
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
                _emit(json.dumps(cursor_response))
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
        _emit("{}")

    except Exception as e:
        # Log errors but still output {} to not break Cursor
        log_error(f"Exception in main: {str(e)}", 'general')
        try:
            print("{}", file=sys.stderr)
            print(f"Error: {redact_secrets(str(e), _cached_api_key)}", file=sys.stderr)
        except (BrokenPipeError, OSError):
            pass
        _emit("{}")


if __name__ == '__main__':
    main()
