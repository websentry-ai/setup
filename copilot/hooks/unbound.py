#!/usr/bin/env python3
"""
Real-time GitHub Copilot hook event processor.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import base64
import json
import io
import os
import ntpath
import platform
import posixpath
import stat
import subprocess
from pathlib import Path, PureWindowsPath
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re
import shlex
import sqlite3
import shutil
import struct
import urllib.request
import uuid
from contextlib import closing
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse, urlunsplit


def _copilot_home():
    return Path(os.environ.get('COPILOT_HOME') or Path.home() / '.copilot').expanduser()


def _copilot_config_path():
    return _copilot_home() / 'config.json'


def _detect_cloud():
    """A cloud agent sandbox: ephemeral disk, no device, no signed-in user, no approver.

    Not the variable alone — anyone can export it, and cloud mode drops the device probe
    and takes the repo gate's answer from the environment. The deciding fact is that the
    cloud loader streams the hook and never writes it down, so an installed hook is a file
    on disk and this is not.
    """
    if not os.environ.get('COPILOT_AGENT_SESSION_ID'):
        return False
    if getattr(sys, 'frozen', False) or os.environ.get('UNBOUND_HOOK_FROZEN') == '1':
        return False
    try:
        return not os.path.isfile(os.path.abspath(__file__))
    except Exception:
        return False


RUNNING_CLOUD = _detect_cloud()


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
IDENTITY_CACHE_PATH = Path.home() / ".unbound" / "identity.json"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

# Use user's home directory for logs
LOG_DIR = Path('/tmp/unbound-copilot') if RUNNING_CLOUD else _copilot_home() / "hooks"
AUDIT_LOG = LOG_DIR / "agent-audit.log"
ERROR_LOG_READ_LIMIT = 256 * 1024
ERROR_LOG = LOG_DIR / "error.log"
LAST_REPORT_FILE = LOG_DIR / ".last_error_report"

MCP_DIAG_STAMP_DIR = LOG_DIR / "mcp-diag"
MCP_DIAG_COOLDOWN_SECONDS = 6 * 3600
MCP_DIAG_VERSION = "copilot-v1"
MCP_DIAG_MAX_REPORT_CHARS = 200 * 1024  # stay well under the gateway's 256KB cap
MCP_DIAG_UPLOAD_TIMEOUT_SECONDS = 30
# ~/.claude.json carries per-project history and can run to megabytes.
MCP_DIAG_MAX_CONFIG_BYTES = 20 * 1024 * 1024

# Matches the backend's model-name column, which truncates to the same length before the
# name reaches the catalog every tenant reads.
MAX_MODEL_NAME_CHARS = 255

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# discovery runs from the locally installed binary instead of a GitHub-fetched
# install.sh. UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without
# freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

SHELL_TOOLS = {'bash', 'shell', 'powershell', 'run_in_terminal', 'runInTerminal', 'terminal'}
READ_TOOLS = {'read_file', 'readFile', 'view', 'cat'}
WRITE_TOOLS = {'create_file', 'create', 'createFile', 'write', 'write_file', 'new_file'}
EDIT_TOOLS = {
    'str_replace', 'edit_file', 'editFile', 'apply_patch', 'insert_edit',
    'replace_string_in_file', 'multi_replace_string_in_file',
    # The cloud agent's name for it; unmapped it canonicalises to nothing and the write is waved through.
    'edit',
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
MANAGED_SKILLS_ROOT = _copilot_home() / 'skills'
UNBOUND_SKILL_PREFIX = 'unbound-'
UNBOUND_SKILL_MARKER = '.unbound-managed'
SKILL_POLICY_STATE_ROOT = Path.home() / '.unbound' / 'skill-policy' / 'copilot'
SKILLS_SYNC_LOCK_PATH = SKILL_POLICY_STATE_ROOT / 'sync.lock'
SKILLS_SYNC_STALE_LOCK_SECONDS = 5 * 60
SKILLS_SYNC_TIMEOUT_SECONDS = 10
SKILL_POLICY_TOOL = 'copilot'
SKILL_POLICY_API_KEY_ENV = 'UNBOUND_COPILOT_API_KEY'
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
    try:
        installed = _skill_policy_visible_inventory(event or {}, installed)
    except Exception as exc:
        log_error(f"skill visible inventory failed: {exc}", 'skill_injection')
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


def _skill_policy_session_id(event):
    return str(event.get('session_id') or event.get('sessionId') or '')


def _skill_policy_turn_key(event):
    session_id = _skill_policy_session_id(event)
    if not session_id:
        return ''
    anchor = get_turn_start_timestamp_for_session(session_id) or event.get('promptId') or event.get('prompt_id')
    return f'{session_id}:{anchor}' if anchor else ''


def _copilot_inventory_path(session_id):
    digest = hashlib.sha256(session_id.encode('utf-8', 'replace')).hexdigest()
    return SKILL_POLICY_STATE_ROOT / 'sessions' / f'{digest}.json'


def _snapshot_copilot_skill_inventory(event):
    session_id = _skill_policy_session_id(event)
    if not session_id:
        return
    try:
        target = _copilot_inventory_path(session_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(installed_skill_report(), sort_keys=True)
        fd, temp_path = tempfile.mkstemp(dir=str(target.parent), prefix='.inventory-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
                temp_file.write(payload)
            os.replace(temp_path, target)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
    except Exception as exc:
        log_error(f"copilot skill inventory snapshot failed: {exc}", 'skill_injection')


def _skill_policy_visible_inventory(event, physical):
    """Copilot answers a skill installed mid-session with "Skill not found" and does
    not fall back to a file search the way Cursor does, so report only what was on
    disk at SessionStart and let the rest land in the next session."""
    session_id = _skill_policy_session_id(event)
    if not session_id:
        return physical
    try:
        value = json.loads(_copilot_inventory_path(session_id).read_text(encoding='utf-8'))
        if not isinstance(value, list):
            return []
        current = {
            (entry.get('slug'), entry.get('sha256'))
            for entry in physical if isinstance(entry, dict)
        }
        return [
            entry for entry in value
            if isinstance(entry, dict) and (entry.get('slug'), entry.get('sha256')) in current
        ]
    except OSError:
        return physical
    except Exception:
        return []


def _copilot_transcript_path(event):
    candidates = (
        event.get('transcript_path'),
        event.get('transcriptPath'),
        _transcript_path_for_session(event),
    )
    for path in candidates:
        if isinstance(path, str) and path and os.path.isfile(path):
            return path
    session_id = _skill_policy_session_id(event)
    if not session_id or not _safe_skill_segment(session_id):
        return None
    try:
        candidate = _copilot_home() / 'session-state' / session_id / 'events.jsonl'
        return str(candidate) if candidate.is_file() else None
    except OSError:
        return None


def _skill_policy_loaded_facts(event):
    transcript = _copilot_transcript_path(event)
    if not isinstance(transcript, str) or not transcript:
        return {'loaded': set(), 'session_count': 0}
    loaded = set()
    observed = set()
    try:
        lines = _skill_policy_transcript_tail(transcript)
        turns = 0
        in_window = True
        for raw in reversed(lines):
            try:
                entry = json.loads(raw)
            except Exception:
                continue
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get('type')
            if entry_type == 'assistant.turn_start':
                turns += 1
                if turns > SKILL_LOADED_WINDOW:
                    in_window = False
                continue
            if entry_type != 'skill.invoked':
                continue
            data = entry.get('data')
            if not isinstance(data, dict):
                continue
            name = next((data.get(key) for key in ('name', 'skillName', 'skill_name', 'skill')
                         if isinstance(data.get(key), str) and data.get(key)), '')
            slug = name[len(UNBOUND_SKILL_PREFIX):] if name.startswith(UNBOUND_SKILL_PREFIX) else ''
            if _skill_policy_valid_slug(slug):
                observed.add(slug)
                if in_window:
                    loaded.add(slug)
    except OSError:
        pass
    try:
        with open(transcript, 'rb') as transcript_file:
            for raw in transcript_file:
                try:
                    entry = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(entry, dict) or entry.get('type') != 'skill.invoked':
                    continue
                data = entry.get('data')
                if not isinstance(data, dict):
                    continue
                name = next((data.get(key) for key in ('name', 'skillName', 'skill_name', 'skill')
                             if isinstance(data.get(key), str) and data.get(key)), '')
                slug = name[len(UNBOUND_SKILL_PREFIX):] if name.startswith(UNBOUND_SKILL_PREFIX) else ''
                if _skill_policy_valid_slug(slug):
                    observed.add(slug)
    except OSError:
        pass
    return {'loaded': loaded, 'session_count': len(observed)}


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
                'content_hash': _skill_content_hash(path),
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
                'content_hash': _skill_content_hash(path),
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


def _curl_base():
    """curl argv prefix, with -q first when it is needed.

    -q makes curl ignore ~/.curlrc. In the sandbox that file is agent-writable and a
    single `insecure` or `resolve` line there redirects the gateway POST below to a server
    of the agent's own -- which answers the pre-tool check, so it decides allow or deny.
    Not on a laptop: there the same file is how a corporate proxy is configured.
    """
    return ["curl", "-q"] if RUNNING_CLOUD else ["curl"]


def report_error_to_gateway(message, category='general', api_key=None, extra=None):
    """Fire-and-forget error report to gateway. Never blocks, never raises."""
    global _reporting_error
    if _reporting_error or not api_key or not _should_report():
        return
    _reporting_error = True
    message = redact_secrets(message, api_key)
    try:
        entry = {'message': message, 'timestamp': datetime.utcnow().isoformat() + 'Z', 'category': category}
        if isinstance(extra, dict):
            entry.update(extra)
        payload = json.dumps({
            'errors': [entry],
            'hook_source': 'copilot',
        })
        proc = subprocess.Popen(
            _curl_base() + ["-fsSL", "-X", "POST",
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


def _open_regular(path, mode):
    """Open a regular file in LOG_DIR, or None: a planted FIFO there would block."""
    flags = {'a': os.O_WRONLY | os.O_APPEND | os.O_CREAT,
             'r': os.O_RDONLY, 'rb': os.O_RDONLY,
             'w': os.O_WRONLY | os.O_CREAT | os.O_TRUNC}[mode]
    flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(str(path), flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    if mode == 'rb':
        return os.fdopen(fd, mode)
    return os.fdopen(fd, mode, encoding='utf-8')


def log_error(message, category='general', extra=None):
    """Log error with timestamp to error.log, keeping only last 25 errors."""
    message = redact_secrets(message, _cached_api_key)
    timestamp = datetime.now().astimezone().isoformat().replace('+00:00', 'Z')
    error_entry = f"{timestamp}: {message}\n"

    try:
        handle = _open_regular(ERROR_LOG, 'a')
        if handle is None:
            return
        with handle as f:
            f.write(error_entry)

        # Keep only last 25 errors
        handle = _open_regular(ERROR_LOG, 'rb')
        if handle is not None:
            with handle as f:
                size = os.fstat(f.fileno()).st_size
                if size > ERROR_LOG_READ_LIMIT:
                    f.seek(size - ERROR_LOG_READ_LIMIT)
                    f.readline()
                lines = f.read(ERROR_LOG_READ_LIMIT).decode('utf-8', 'replace').splitlines(True)
            if len(lines) > 25:
                handle = _open_regular(ERROR_LOG, 'w')
                if handle is not None:
                    with handle as f:
                        f.writelines(lines[-25:])
    except Exception:
        pass

    # Report to gateway (fire-and-forget)
    report_error_to_gateway(message, category, _cached_api_key, extra)


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



# In-process in the sandbox: the cache file sits in agent-writable /tmp, and every reader
# of it -- native-write short-circuit, repo gate, fail-open action -- would trust a plant.
_CLOUD_POLICY_CACHE = {}


def _read_policy_cache_raw():
    """Read and JSON-parse the policy cache file. Returns None on missing/corrupt."""
    if RUNNING_CLOUD:
        return dict(_CLOUD_POLICY_CACHE) or None
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


def _split_attribution_footer(reason, trace_id=None):
    """(reason without its trailing footer, footer), so the footer can be shown last."""
    footer = _attribution_footer(trace_id)
    # An ask reason carries one trailing newline after the footer (Claude Code layout).
    body = reason.rstrip('\n') if isinstance(reason, str) else ''
    if body.endswith(footer):
        return body[:-len(footer)], footer
    return reason, ''


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
        if not RUNNING_CLOUD:
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
        if RUNNING_CLOUD:
            _CLOUD_POLICY_CACHE.clear()
            _CLOUD_POLICY_CACHE.update(cache)
            return
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


# preToolUse reads this file twice before deciding, and in the sandbox it is agent-writable:
# unbounded, a bloated file stalls the read until the hook is killed, which fails OPEN.
CLOUD_AUDIT_READ_LIMIT = 4 * 1024 * 1024


def _load_audit_tail():
    """At most CLOUD_AUDIT_READ_LIMIT bytes from the end of the audit log.

    The budget is on the read itself, not just where it starts. Iterating the handle would
    follow the file as it grows, so a process appending in the background could keep the
    loop going indefinitely -- the same stall the cap exists to prevent.
    """
    logs = []
    try:
        handle = _open_regular(AUDIT_LOG, 'rb')
        if handle is None:
            return logs
        with handle as f:
            size = os.fstat(f.fileno()).st_size
            if size > CLOUD_AUDIT_READ_LIMIT:
                f.seek(size - CLOUD_AUDIT_READ_LIMIT)
                f.readline()  # the seek lands mid-line; that fragment is not parseable
            data = f.read(CLOUD_AUDIT_READ_LIMIT)
    except Exception:
        return logs
    for raw in data.splitlines():
        line = raw.decode('utf-8', 'replace').strip()
        if not line:
            continue
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a line truncated by the budget is simply dropped
    return logs


def load_existing_logs():
    """Load existing logs from agent-audit.log into memory."""
    logs = []
    if AUDIT_LOG.exists():
        # Always bounded in the sandbox: the file is agent-writable and read twice per decision.
        if RUNNING_CLOUD:
            return _load_audit_tail()
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
        handle = _open_regular(AUDIT_LOG, 'a')
        if handle is None:
            return
        with handle as f:
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


def copilot_surface(transcript_path):
    """Which Copilot wrote this turn. The two stores are the only thing that says so,
    and the same check already picks which one to read usage from."""
    if RUNNING_CLOUD:
        return 'cloud'
    if not isinstance(transcript_path, str) or not transcript_path:
        return None
    return 'cli' if Path(transcript_path).stem == 'events' else 'vscode'


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
                             pending_turns=_UNSET):
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


def build_turn_request_id(session_id, turn_id):
    """Stable id for one turn, keyed on the transcript's own id for its user message.

    Unique per request by construction, which a hash of the turn's text is not: a session
    can hold two turns whose prompt AND reply are byte-identical.
    KEEP IN SYNC: ai-gateway-data coding_tools_backfill_service, which derives the same
    id and must accept this keying before a device running it reports a turn."""
    return str(uuid.uuid5(
        uuid.NAMESPACE_OID, 'turn:copilot:%s:%s' % (session_id, turn_id)))


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


def is_autopilot_continuation(data):
    """True for the user.message autopilot writes to nudge itself on, which nobody typed.

    It carries no content -- the instruction sits in transformedContent -- so treating it
    as a prompt starts a turn the user never began. VS Code emits no such entry.

    Empty content is required whichever marker matched, so text a user actually typed is
    reported however the entry around it is labelled."""
    if not isinstance(data, dict):
        return False
    content = data.get('content')
    empty = not (content.strip() if isinstance(content, str) else content)
    return empty and bool(data.get('isAutopilotContinuation')
                          or data.get('source') == 'system')


def _email_domain(email: Optional[str]) -> Optional[str]:
    try:
        if email and '@' in email:
            domain = email.rsplit('@', 1)[1].strip().lower()
            return domain or None
    except Exception:
        pass
    return None


def _config_email() -> Optional[str]:
    """The email the installer wrote to ~/.unbound/config.json. Never raises."""
    try:
        with open(UNBOUND_CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.loads(f.read())
        if isinstance(cfg, dict):
            return (cfg.get('email') or '').strip() or None
    except Exception:
        pass
    return None


def _copilot_login() -> Tuple[Optional[str], Optional[str]]:
    """The account `copilot login` recorded. JSONC, so comments come out first."""
    try:
        raw = _copilot_config_path().read_text(encoding='utf-8')
    except Exception:
        return None, None
    try:
        cfg = json.loads(re.sub(r'^\s*//.*$', '', raw, flags=re.M))
        user = cfg.get('lastLoggedInUser')
        if not isinstance(user, dict):
            users = cfg.get('loggedInUsers')
            user = users[0] if isinstance(users, list) and users else None
        if not isinstance(user, dict):
            return None, None
        login = (user.get('login') or '').strip() or None
        host = (user.get('host') or '').strip() or None
        return login, host
    except Exception:
        log_error('copilot config unparsable, account not reported', 'config')
        return None, None


_COPILOT_USER_CACHE_MAX_BYTES = 1024 * 1024
_COPILOT_USER_CACHE_MAX_AGE_SECONDS = 7 * 24 * 3600


def _copilot_user_cache_path() -> Optional[Path]:
    if _is_windows():
        base = os.environ.get('LOCALAPPDATA')
        return Path(base) / 'copilot' / 'copilot-user-cache.json' if base else None
    if platform.system() == 'Darwin':
        return Path.home() / 'Library' / 'Caches' / 'copilot' / 'copilot-user-cache.json'
    return Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'copilot' / 'copilot-user-cache.json'


def _github_org_id(response: Dict) -> Optional[str]:
    """The seat's org: organization_login_list names the orgs granting it, organization_list carries their IDs."""
    orgs = response.get('organization_list')
    seat = response.get('organization_login_list')
    seat = {o.lower() for o in seat if isinstance(o, str)} if isinstance(seat, list) else None
    ids = sorted(o['id'] for o in orgs if isinstance(o, dict) and isinstance(o.get('id'), int)
                 and (seat is None or str(o.get('login') or '').lower() in seat)) if isinstance(orgs, list) else []
    return str(ids[0]) if ids else None


def _copilot_cached_seat(login: str) -> Tuple[Optional[str], Optional[str]]:
    path = _copilot_user_cache_path()
    try:
        if path is None or path.stat().st_size > _COPILOT_USER_CACHE_MAX_BYTES:
            return None, None
        raw = path.read_text(encoding='utf-8')
        entries = json.loads(re.sub(r'^\s*//.*$', '', raw, flags=re.M)).get('copilotUserCache')
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, AttributeError) as error:
        log_error(f'copilot user cache unreadable: {type(error).__name__}', 'identity')
        return None, None
    newest = None
    for entry in entries.values() if isinstance(entries, dict) else ():
        response = entry.get('response') if isinstance(entry, dict) else None
        if not isinstance(response, dict) or str(response.get('login') or '').lower() != login.lower():
            continue
        try:
            at = datetime.fromisoformat(str(entry.get('retrievedAt')).replace('Z', '+00:00')).timestamp()
        except ValueError:
            continue
        if time.time() - at > _COPILOT_USER_CACHE_MAX_AGE_SECONDS:
            continue
        if newest is None or at > newest[0]:
            newest = (at, response)
    if newest is None:
        return None, None
    response = newest[1]
    sku = response.get('access_type_sku')
    return (sku.strip() or None) if isinstance(sku, str) else None, _github_org_id(response)


_VSCODE_COPILOT_ACCOUNT_KEY = 'github.copilot-github'
_VSCODE_COPILOT_CHAT_STATE_KEY = 'GitHub.copilot-chat'
_VSCODE_COPILOT_STATE_MAX_BYTES = 4 * 1024 * 1024


def _vscode_state_values(path, keys):
    try:
        uri = f'{path.resolve().as_uri()}?mode=ro'
        marks = ','.join('?' * len(keys))
        with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as connection:
            rows = connection.execute(
                f'SELECT key, value FROM ItemTable WHERE key IN ({marks}) '
                f'AND length(CAST(value AS BLOB)) <= ?',
                (*keys, _VSCODE_COPILOT_STATE_MAX_BYTES)).fetchall()
    except (OSError, sqlite3.Error) as error:
        log_error(f'vscode copilot account read failed path={path} err={error}', 'identity')
        return {}
    values = {}
    for key, value in rows:
        if isinstance(value, bytes):
            value = value.decode('utf-8', 'replace')
        if isinstance(value, str):
            values[key] = value
    return values


def _vscode_user_dir_of(transcript_path) -> Optional[Path]:
    if not isinstance(transcript_path, str) or not transcript_path:
        return None
    for parent in Path(transcript_path).parents:
        if parent.name in ('workspaceStorage', 'globalStorage'):
            return parent.parent
    return None


def _vscode_copilot_account(user_dir: Optional[Path] = None) -> Tuple[Optional[str], Optional[str]]:
    """The login key survives a sign-out; the sku does not."""
    databases = []
    for user_dir in [user_dir] if user_dir else _vscode_user_dirs():
        path = user_dir / 'globalStorage' / 'state.vscdb'
        try:
            databases.append((path.stat().st_mtime_ns, path))
        except OSError:
            continue
    for _, path in sorted(databases, reverse=True):
        values = _vscode_state_values(path, (_VSCODE_COPILOT_ACCOUNT_KEY, _VSCODE_COPILOT_CHAT_STATE_KEY))
        login = (values.get(_VSCODE_COPILOT_ACCOUNT_KEY) or '').strip()
        if not login:
            continue
        try:
            chat = json.loads(values.get(_VSCODE_COPILOT_CHAT_STATE_KEY) or '{}')
        except json.JSONDecodeError:
            chat = {}
        chat = chat if isinstance(chat, dict) else {}
        sku = chat.get('exp.github.copilot.sku')
        sku = sku.strip() if isinstance(sku, str) else ''
        return (login, sku) if sku else (None, None)
    return None, None


def _vscode_no_account_reason(user_dir: Optional[Path] = None) -> str:
    paths = [d / 'globalStorage' / 'state.vscdb' for d in ([user_dir] if user_dir else _vscode_user_dirs())]
    paths = [p for p in paths if p.is_file()]
    if not paths:
        return 'vscode_not_found'
    read_any = False
    for path in sorted(paths, key=lambda p: p.stat().st_mtime_ns, reverse=True):
        try:
            with closing(sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=1.0)) as connection:
                row = connection.execute('SELECT value FROM ItemTable WHERE key = ?',
                                         (_VSCODE_COPILOT_ACCOUNT_KEY,)).fetchone()
        except (OSError, sqlite3.Error):
            continue
        read_any = True
        login = row[0] if row else None
        login = login.decode('utf-8', 'replace') if isinstance(login, bytes) else login
        if isinstance(login, str) and login.strip():
            return 'vscode_signed_out'
    return 'vscode_no_copilot_login' if read_any else 'vscode_unreadable'


def _copilot_cli_no_account_reason() -> str:
    tokens = ('COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')
    return 'env_token' if any(os.environ.get(v) for v in tokens) else 'cli_no_login'


def read_account_identity(event: Optional[Dict] = None, surface: Optional[str] = None,
                          transcript_path: Optional[str] = None) -> Dict:
    """The signed-in account, keyed by GitHub login rather than address."""
    plan = org = None
    if surface == 'vscode':
        login, plan = _vscode_copilot_account(_vscode_user_dir_of(transcript_path))
        host = 'https://github.com' if login else None
        if login:
            cached_plan, cached_org = _copilot_cached_seat(login)
            org = cached_org if cached_plan == plan else None
    elif surface == 'cloud':
        login, host = _copilot_login()
    else:
        login, host = _copilot_login()
        if login and urlparse(host or 'https://github.com').hostname == 'github.com':
            plan, org = _copilot_cached_seat(login)
            if not plan:
                org = None
                vscode_login, vscode_plan = _vscode_copilot_account()
                if vscode_login and vscode_login.lower() == login.lower():
                    plan = vscode_plan
    if not login:
        try:
            reason = (_vscode_no_account_reason(_vscode_user_dir_of(transcript_path)) if surface == 'vscode'
                      else 'cloud_no_login' if surface == 'cloud' else _copilot_cli_no_account_reason())
        except Exception:
            reason = 'unknown'
        return {'org_id': None, 'plan': None, 'auth_mode': None,
                'user_email': None, 'email_domain': None,
                'account_login': None, 'account_host': None, 'account_reason': reason}
    return {
        'org_id': org,
        'plan': plan,
        'auth_mode': 'subscription',
        # Never user_email: the gateway maps that to device.email, which
        # provisions and hands off devices to whatever address it names.
        'user_email': None,
        'email_domain': None,
        'account_login': login,
        'account_host': host,
    }


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
    """Hardware serial, falling back to a per-install id. Placeholder values are
    rejected so two machines never collide on the same fake serial."""
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
    """Hardware serial, probed once and cached. probe=False reads the cache only, so
    the latency-critical paths never run a subprocess. Never raises."""
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


# The hook's claim about where the actor came from, not proof: written in the sandbox and
# sent with the actor. Attributing cost or policy must re-check it against GitHub.
ACTOR_SOURCE_API = 'github_api'
ACTOR_SOURCE_ENV = 'runner_env'

_ENV_ACTOR_SERVICE = {'copilot', 'copilot-swe-agent', 'github-actions', 'github-copilot'}


def _env_actor() -> Optional[str]:
    """The login the runner says triggered the job. The agent is not a person, and appears
    both with and without a `[bot]` suffix."""
    for var in ('GITHUB_TRIGGERING_ACTOR', 'GITHUB_ACTOR'):
        login = (os.environ.get(var) or '').strip()
        if login and '[bot]' not in login.lower() and login.lower() not in _ENV_ACTOR_SERVICE:
            return login
    return None


CLOUD_ACTOR_TASK_SCAN = 5
# Whole lookup, not per call: unbounded it outlasts the agentStop timeout and the turn goes
# unreported. A name is worth less than the audit record.
CLOUD_ACTOR_BUDGET = 8.0
_cloud_actor_memo = {}
# Why the last call named nobody. Reported once a session: the lookup has several ways to
# come back empty and the row alone cannot tell a missing token from a refused one.
_cloud_api_reason = None


def _github_api(path: str, deadline: Optional[float] = None) -> Optional[Dict]:
    """GitHub's REST API with the sandbox's own token. Never raises."""
    global _cloud_api_reason
    # An Enterprise Server token must not reach public GitHub; _copilot_seat refuses the
    # same case. Unset is refused too.
    if urlparse(os.environ.get('GITHUB_SERVER_URL') or '').hostname != 'github.com':
        _cloud_api_reason = 'server_url'
        return None
    # The two the cloud sandbox documents. GITHUB_TOKEN is documented as not set there, and
    # the laptop names the seat lookup uses do not exist in it either.
    for var in ('GITHUB_COPILOT_API_TOKEN', 'GITHUB_COPILOT_GIT_TOKEN'):
        token = (os.environ.get(var) or '').strip()
        if token:
            break
    else:
        _cloud_api_reason = 'no_token'
        return None
    # Not 0: a --max-time formatting to 0.0 is unlimited to curl.
    left = 5.0 if deadline is None else min(5.0, deadline - time.monotonic())
    if left < 0.1:
        _cloud_api_reason = 'budget_spent'
        return None
    result = subprocess.run(
        _curl_base() + ["-fsS", "--max-time", "%.1f" % left, "-H", "@-",
                        "https://api.github.com/%s" % path],
        input=("Authorization: token %s\n" % token).encode(),
        capture_output=True, timeout=left + 5)
    if result.returncode != 0:
        # The token rides stdin, never argv, so curl's own message cannot carry it.
        _cloud_api_reason = '%s rc=%d %s' % (
            var, result.returncode, result.stderr.decode('utf-8', 'replace').strip()[:120])
        return None
    return json.loads(result.stdout)


def _cloud_session_user_id(repo: str, session: str, deadline: float) -> Optional[int]:
    """The task list carries no session ids, so each task is opened until this one turns up.
    Newest first: a session's own task is the newest on the repo."""
    tasks = (_github_api('agents/repos/%s/tasks' % repo, deadline) or {}).get('tasks') or []
    for task in tasks[:CLOUD_ACTOR_TASK_SCAN]:
        if time.monotonic() >= deadline:
            return None
        detail = _github_api('agents/repos/%s/tasks/%s' % (repo, task.get('id')), deadline)
        for entry in (detail or {}).get('sessions') or []:
            if entry.get('id') == session:
                return (entry.get('user') or {}).get('id')
    return None


def _cloud_session_actor(repo: str, session: str) -> Optional[str]:
    """The login GitHub records for this session.

    Memoised per process, never to disk: the sandbox is agent-writable, so a cache file
    would let it plant the name this call exists to establish.
    """
    if session in _cloud_actor_memo:
        return _cloud_actor_memo[session]
    login = None
    deadline = time.monotonic() + CLOUD_ACTOR_BUDGET
    try:
        user_id = _cloud_session_user_id(repo, session, deadline)
        if user_id:
            login = ((_github_api('user/%s' % user_id, deadline) or {}).get('login')
                     or '').strip() or None
    except Exception as e:
        log_error('cloud session actor lookup failed: %s: %s' % (type(e).__name__, e), 'identity')
    if login is None:
        log_error('cloud session actor unresolved: %s' % (_cloud_api_reason or 'session_not_found'),
                  'identity')
    _cloud_actor_memo[session] = login
    return login


def build_github_context() -> Optional[Dict]:
    """Cloud-agent provenance. None on a laptop, where the device identity applies."""
    if not RUNNING_CLOUD:
        return None
    repo = os.environ.get('GITHUB_REPOSITORY')
    session = os.environ.get('COPILOT_AGENT_SESSION_ID')
    # GitHub's record first, the runner's unverified variables only when it cannot answer.
    # Each says which it was, or a reader cannot tell them apart.
    actor = _cloud_session_actor(repo, session) if repo and session else None
    source = ACTOR_SOURCE_API if actor else None
    if not actor:
        actor = _env_actor()
        source = ACTOR_SOURCE_ENV if actor else None
    context = {
        'actor': actor,
        'actor_source': source,
        'repo': repo,
        'session': session,
        'event': os.environ.get('COPILOT_JOB_EVENT_TYPE'),
    }
    return {key: value for key, value in context.items() if value} or None


COPILOT_SEAT_CACHE_PATH = Path.home() / ".unbound" / "copilot_seat.json"
COPILOT_SEAT_TTL = 24 * 3600


def _fetch_copilot_seat() -> Optional[Dict]:
    """GitHub's view of the seat. Never reads Copilot's keychain item: only
    Copilot's own binary may, and anything else prompts the user."""
    for var in ('COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'):
        token = (os.environ.get(var) or '').strip()
        if token:
            curl = _windows_system32_path("curl.exe") if _is_windows() else "curl"
            result = subprocess.run(
                [curl, "-fsS", "--max-time", "5", "-H", "@-",
                 "https://api.github.com/copilot_internal/user"],
                input=("Authorization: token %s\n" % token).encode(),
                capture_output=True, timeout=10)
            return json.loads(result.stdout) if result.returncode == 0 else None
    gh = shutil.which('gh')
    if gh:
        result = subprocess.run([gh, 'api', '/copilot_internal/user'],
                                capture_output=True, timeout=10)
        if result.returncode == 0:
            return json.loads(result.stdout)
    return None


def _copilot_seat(login: str, host: Optional[str], probe: bool) -> Tuple[Optional[str], Optional[str]]:
    """Plan and org of the seat, which Copilot keeps nowhere on disk. Cached a
    day; only the end-of-turn path (probe) asks GitHub. Never raises."""
    try:
        cached = json.loads(COPILOT_SEAT_CACHE_PATH.read_text(encoding='utf-8'))
        if cached.get('v') == 3 and cached.get('login') == login and time.time() - cached.get('at', 0) < COPILOT_SEAT_TTL:
            return cached.get('plan'), cached.get('org')
    except Exception:
        pass
    # An unknown host may be Enterprise Server; its token must not reach github.com.
    if not probe or urlparse(host or '').hostname != 'github.com':
        return None, None
    try:
        seat = _fetch_copilot_seat()
    except Exception:
        seat = None
    plan = org = None
    # Another account's token (a different gh login) must not lend its seat.
    if isinstance(seat, dict) and str(seat.get('login') or '').lower() == login.lower():
        plan = next((seat[k] for k in ('access_type_sku', 'copilot_plan') if isinstance(seat.get(k), str) and seat[k]), None)
        org = _github_org_id(seat)
    # A miss is cached too, or a machine with no token asks GitHub every turn.
    try:
        COPILOT_SEAT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = COPILOT_SEAT_CACHE_PATH.parent / (".copilot_seat.%d.tmp" % os.getpid())
        tmp.write_text(json.dumps({'v': 3, 'login': login, 'plan': plan, 'org': org, 'at': time.time()}),
                       encoding='utf-8')
        os.replace(str(tmp), str(COPILOT_SEAT_CACHE_PATH))
    except Exception:
        pass
    return plan, org


def build_account_identity(event: Optional[Dict] = None, probe: bool = False,
                           surface: Optional[str] = None, transcript_path: Optional[str] = None) -> Dict:
    """The account plus the device serial. The event is unused here. Never raises."""
    try:
        identity = read_account_identity(event, surface, transcript_path)
        if not isinstance(identity, dict):
            identity = {}
    except Exception:
        identity = {}
    try:
        if identity.get('account_login') and not (identity.get('plan') and identity.get('org_id')):
            plan, org = _copilot_seat(
                identity['account_login'], identity.get('account_host'), probe)
            if not identity.get('plan'):
                identity['plan'], identity['org_id'] = plan, identity.get('org_id') or org
            elif plan == identity['plan']:
                identity['org_id'] = org
    except Exception:
        pass
    try:
        serial = _device_serial(probe=probe)
        if serial:
            identity['device_serial'] = serial
    except Exception:
        pass
    return identity


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
        # Cache-only: called once per waiting turn, so probing here would cost a
        # 10s command on each of them.
        'account_identity': build_account_identity(surface=copilot_surface(transcript_path),
                                                   transcript_path=transcript_path),
        # A re-send is the same turn and needs the same provenance; unlabelled, the control
        # plane falls back to the API key's owner and bills the turn to them.
        'agent_surface': copilot_surface(transcript_path),
        'github': build_github_context(),
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
            # Autopilot's nudge is not the next prompt, so it does not close the turn.
            # Matches the turn this rebuild is completing, which spans it too.
            if is_autopilot_continuation(data):
                continue
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
        for key in ('url', 'command', 'args', 'type', 'cwd')
        if server.get(key)
    }
    return result or None


def _mcp_launch_identity(server):
    if not isinstance(server, dict):
        return None
    args = server.get('args')
    return (
        server.get('command'),
        server.get('url'),
        tuple(args) if isinstance(args, list) else (),
        server.get('cwd'),
    )


def _mcp_provider_identity(server):
    if not isinstance(server, dict):
        return None
    additional_data = server.get('additional_data')
    if not isinstance(additional_data, dict):
        return None
    provider_id = additional_data.get('providerId')
    server_id = additional_data.get('providerServerId')
    if not isinstance(provider_id, str) or not isinstance(server_id, str):
        return None
    return provider_id, server_id


_MCP_CONFIG_MAX_BYTES = 1_000_000
_VSCODE_MCP_PROVIDER_CACHE_KEY = 'mcp.extCachedServers'
_VSCODE_MCP_PROVIDER_CACHE_MAX_BYTES = 5 * 1024 * 1024
_VSCODE_MCP_STATE_DATABASE_MAX_COUNT = 100
_VSCODE_MCP_PROVIDER_MAX_COUNT = 200
_VSCODE_MCP_SERVERS_PER_PROVIDER_MAX_COUNT = 100
_VSCODE_MCP_SERVER_MAX_COUNT = 500
_VSCODE_WORKSPACE_METADATA_MAX_BYTES = 64 * 1024


def _vscode_mcp_state_databases():
    paths = []
    patterns = (
        'globalStorage/state.vscdb',
        'workspaceStorage/*/state.vscdb',
        'profiles/*/globalStorage/state.vscdb',
        'profiles/*/workspaceStorage/*/state.vscdb',
    )
    for user_dir in _vscode_user_dirs():
        for pattern in patterns:
            try:
                paths.extend(path for path in user_dir.glob(pattern) if path.is_file())
            except OSError:
                continue

    def modified_at(path):
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return -1

    ordered = sorted(set(paths), key=lambda path: (-modified_at(path), str(path)))
    return ordered[:_VSCODE_MCP_STATE_DATABASE_MAX_COUNT]


def _read_vscode_mcp_provider_cache(path):
    try:
        database_uri = f'{path.resolve().as_uri()}?mode=ro'
        with closing(sqlite3.connect(database_uri, uri=True, timeout=1.0)) as connection:
            size_row = connection.execute(
                'SELECT length(CAST(value AS BLOB)) FROM ItemTable WHERE key = ? LIMIT 1',
                (_VSCODE_MCP_PROVIDER_CACHE_KEY,),
            ).fetchone()
            if not size_row or not isinstance(size_row[0], int):
                return None
            if size_row[0] > _VSCODE_MCP_PROVIDER_CACHE_MAX_BYTES:
                return None
            value_row = connection.execute(
                'SELECT value FROM ItemTable WHERE key = ? LIMIT 1',
                (_VSCODE_MCP_PROVIDER_CACHE_KEY,),
            ).fetchone()
    except (OSError, sqlite3.Error) as error:
        log_error(f'copilot mcp provider cache read failed path={path} err={error}', 'mcp_config')
        return None

    if not value_row:
        return None
    value = value_row[0]
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    try:
        cache = json.loads(value)
    except json.JSONDecodeError:
        return None
    return cache if isinstance(cache, dict) else None


def _vscode_workspace_uri_path(uri):
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    if parsed.scheme.lower() != 'file':
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', '')) or None

    path = unquote(parsed.path)
    if platform.system() == 'Windows':
        windows_path = path.replace('/', '\\')
        if parsed.netloc:
            return f'\\\\{parsed.netloc}{windows_path}'
        if re.match(r'^/[A-Za-z]:', path):
            windows_path = windows_path[1:]
        return windows_path or None
    if parsed.netloc:
        return f'//{parsed.netloc}{path}'
    return path or None


def _vscode_cache_scope(path):
    for user_dir in _vscode_user_dirs():
        try:
            relative_parts = path.relative_to(user_dir).parts
        except ValueError:
            continue

        if 'workspaceStorage' in relative_parts:
            metadata_path = path.parent / 'workspace.json'
            try:
                with metadata_path.open('rb') as metadata_file:
                    raw_metadata = metadata_file.read(
                        _VSCODE_WORKSPACE_METADATA_MAX_BYTES + 1
                    )
                if len(raw_metadata) > _VSCODE_WORKSPACE_METADATA_MAX_BYTES:
                    return None
                metadata = json.loads(raw_metadata.decode('utf-8'))
            except (OSError, UnicodeDecodeError, ValueError):
                return None
            if not isinstance(metadata, dict):
                return None
            workspace_uri = metadata.get('folder') or metadata.get('workspace')
            if not isinstance(workspace_uri, str) or not workspace_uri:
                return None
            return _vscode_workspace_uri_path(workspace_uri)

        if len(relative_parts) >= 3 and relative_parts[0] == 'profiles':
            return str(user_dir / 'profiles' / relative_parts[1])
        if relative_parts == ('globalStorage', 'state.vscdb'):
            return str(user_dir)
    return None


def _vscode_cache_profile(path):
    for user_dir in _vscode_user_dirs():
        try:
            relative_parts = path.relative_to(user_dir).parts
        except ValueError:
            continue
        if len(relative_parts) >= 2 and relative_parts[0] == 'profiles':
            return relative_parts[1]
    return None


def _running_with_elevated_privileges():
    if platform.system() == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return True
    try:
        return os.geteuid() == 0 or os.geteuid() != os.getuid()
    except (AttributeError, OSError):
        return True


def _vscode_workspace_scope_matches(
    path,
    scope,
    cwd,
    skip_filesystem_probe=False,
):
    if not cwd or 'workspaceStorage' not in path.parts:
        return True
    if '://' in scope or scope.lower().endswith('.code-workspace'):
        return True
    if skip_filesystem_probe:
        path_type = PureWindowsPath if platform.system() == 'Windows' else Path
        path_module = ntpath if platform.system() == 'Windows' else posixpath
        workspace = path_type(path_module.normpath(scope))
        current = path_type(path_module.normpath(cwd))
    else:
        try:
            workspace = Path(scope).resolve()
            current = Path(cwd).resolve()
        except OSError:
            workspace = Path(scope)
            current = Path(cwd)
    return current == workspace or workspace in current.parents


def _vscode_cached_launch_fields(launch, skip_command_probe=False):
    if not isinstance(launch, dict):
        return None
    transport_type = launch.get('type')
    command = launch.get('command')
    if transport_type == 1 and isinstance(command, str) and command:
        args = launch.get('args')
        env = launch.get('env')
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            return None
        if not isinstance(env, dict):
            return None
        fields = {'type': 'stdio', 'command': command}
        fields['args'] = args
        cwd = launch.get('cwd')
        if isinstance(cwd, str) and cwd:
            fields['cwd'] = cwd
        expanded_command = os.path.expandvars(os.path.expanduser(command))
        expanded_cwd = (
            os.path.expandvars(os.path.expanduser(cwd))
            if isinstance(cwd, str)
            else ''
        )
        if platform.system() == 'Windows' and any(
            value.replace('/', '\\').startswith('\\\\')
            for value in (expanded_command, expanded_cwd)
        ):
            return None
        if not skip_command_probe:
            expanded = Path(expanded_command)
            if expanded.is_absolute():
                if not expanded.is_file():
                    return None
            elif cwd:
                expanded_cwd_path = Path(expanded_cwd)
                if (
                    not (expanded_cwd_path / expanded).is_file()
                    and shutil.which(str(expanded)) is None
                ):
                    return None
            elif shutil.which(str(expanded)) is None:
                return None
        return fields
    if transport_type == 2:
        uri = launch.get('uri')
        if not isinstance(uri, dict):
            return None
        scheme = uri.get('scheme')
        authority = uri.get('authority')
        path = uri.get('path', '')
        if (
            not isinstance(scheme, str)
            or scheme.lower() not in ('http', 'https')
            or not isinstance(authority, str)
            or not authority
            or not isinstance(path, str)
        ):
            return None
        parsed = urlparse(urlunsplit((scheme, authority, path, '', '')))
        hostname = parsed.hostname or ''
        if not hostname:
            return None
        if ':' in hostname and not hostname.startswith('['):
            hostname = f'[{hostname}]'
        try:
            port = parsed.port
        except ValueError:
            return None
        netloc = f'{hostname}:{port}' if port is not None else hostname
        return {
            'type': 'http',
            'url': urlunsplit((scheme.lower(), netloc, path, '', '')),
        }
    return None


def _vscode_cached_mcp_servers(cwd=None):
    servers = []
    seen = set()
    skip_filesystem_probe = _running_with_elevated_privileges()
    for path in _vscode_mcp_state_databases():
        scope = _vscode_cache_scope(path)
        profile_id = _vscode_cache_profile(path)
        if scope is None or not _vscode_workspace_scope_matches(
            path,
            scope,
            cwd,
            skip_filesystem_probe,
        ):
            continue
        cache = _read_vscode_mcp_provider_cache(path)
        if not cache:
            continue
        for provider_index, (provider_id, provider) in enumerate(cache.items()):
            if provider_index >= _VSCODE_MCP_PROVIDER_MAX_COUNT:
                break
            if not isinstance(provider_id, str) or not isinstance(provider, dict):
                continue
            cached_servers = provider.get('servers')
            if not isinstance(cached_servers, list):
                continue
            for cached_server in cached_servers[:_VSCODE_MCP_SERVERS_PER_PROVIDER_MAX_COUNT]:
                if len(servers) >= _VSCODE_MCP_SERVER_MAX_COUNT:
                    return servers
                if not isinstance(cached_server, dict):
                    continue
                fields = _vscode_cached_launch_fields(
                    cached_server.get('launch'),
                    skip_filesystem_probe,
                )
                if fields is None:
                    continue
                server_id = cached_server.get('id')
                if not isinstance(server_id, str) or not server_id:
                    continue
                label = cached_server.get('label')
                if not isinstance(label, str) or not label:
                    label = server_id
                identity = (scope, profile_id, provider_id, server_id)
                if identity in seen:
                    continue
                seen.add(identity)
                fields['additional_data'] = {
                    'scope': VSCODE_PROVIDER_CACHE_SCOPE,
                    'providerId': provider_id,
                    'providerServerId': server_id,
                    **(
                        {'providerProfileId': profile_id}
                        if profile_id is not None
                        else {}
                    ),
                }
                servers.append((label, fields))
    return servers


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
    # Require a script extension: matching any path-shaped arg would let a
    # crafted runtime config (e.g. `python3 /etc/passwd`) read arbitrary files.
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


_HOOK_SCRIPT_SNAPSHOT = {}


def _hook_script_snapshot(command, args, cwd):
    """(sha256, base64 body) derived from one read, so the hash reported on the
    policy call and the body the scan uploads can never describe different bytes.
    Holds a single entry: the body is capped, but it is not free."""
    path = _hook_script_path(command, args, cwd)
    if not path:
        return None
    cached = _HOOK_SCRIPT_SNAPSHOT.get(path)
    if cached:
        return cached
    try:
        data = _hook_read_script_bytes(path)
    except OSError as exc:
        log_error("mcp script fingerprint: cannot read %s: %s"
                  % (os.path.basename(path), type(exc).__name__), 'mcp_config')
        return None
    if data is None:
        log_error("mcp script fingerprint: %s is not a regular file" % os.path.basename(path), 'mcp_config')
        return None
    snapshot = (hashlib.sha256(data).hexdigest(),
                base64.b64encode(data).decode('ascii'))
    _HOOK_SCRIPT_SNAPSHOT.clear()
    _HOOK_SCRIPT_SNAPSHOT[path] = snapshot
    return snapshot


def _compute_script_hash(command, args, cwd):
    """sha256 of the local script's contents, or None when it isn't a resolvable
    local script. Matches what the backend recomputes from the uploaded body, so
    the gateway's `script:<hash>` lookup lines up with the stored fingerprint.
    Capped so all clients agree on the hash for large scripts."""
    snapshot = _hook_script_snapshot(command, args, cwd)
    return snapshot[0] if snapshot else None


def _augment_script_hash(result, cwd):
    """Add scriptHash to an MCP server config when it runs a local script, so the
    gateway can fingerprint it as `script:<hash>`."""
    if result and result.get('command'):
        script_hash = _compute_script_hash(result.get('command'), result.get('args'), cwd)
        if script_hash:
            result['scriptHash'] = script_hash
    return result


def _read_script_body_b64(command, args, cwd):
    """base64 of the local script's first _HOOK_MAX_SCRIPT_BYTES bytes (the scan
    body), or None. The backend re-hashes these exact bytes, so this must read the
    same prefix _compute_script_hash hashed."""
    snapshot = _hook_script_snapshot(command, args, cwd)
    return snapshot[1] if snapshot else None


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


def _provider_cache_entries_for_user(provider_servers):
    username = Path.home().name
    entries = []
    for by_user in provider_servers.values():
        if not isinstance(by_user, dict):
            continue
        entry = by_user.get(username)
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _validated_provider_cache_observation(stable_fingerprint, observation):
    if not isinstance(observation, dict):
        return None
    name = observation.get('name')
    url = observation.get('url')
    raw_additional_data = observation.get('additional_data')
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 255
        or not isinstance(url, str)
        or not isinstance(raw_additional_data, dict)
    ):
        return None

    additional_data = {
        'scope': raw_additional_data.get('scope'),
        'providerId': raw_additional_data.get('providerId'),
        'providerServerId': raw_additional_data.get('providerServerId'),
    }
    recomputed = compute_mcp_cache_key(
        name=name,
        command=None,
        url=url,
        args=None,
        additional_data=additional_data,
    )
    if recomputed != stable_fingerprint:
        return None
    provider_server_id = additional_data['providerServerId']
    expected_name = provider_server_id.split('/', 1)[1]
    if name.strip().casefold() != expected_name.strip().casefold():
        return None

    try:
        parsed_url = urlparse(url)
        _ = parsed_url.port
    except ValueError:
        return None
    host = parsed_url.hostname or ''
    # urlparse strips the brackets off an IPv6 host; without them the rebuilt
    # URL is unparseable and stops recomputing to the enclosing fingerprint.
    host = f'[{host}]' if ':' in host else host
    try:
        parsed_port = parsed_url.port
    except ValueError:
        return None
    port = f':{parsed_port}' if parsed_port else ''
    canonical_url = (
        f'{parsed_url.scheme.lower()}://{host}{port}'
        f'{parsed_url.path}'
    )
    return name, {
        'url': canonical_url,
        'additional_data': additional_data,
    }


def _copilot_provider_servers_from_cache(cache):
    provider_servers = cache.get('provider_servers') if isinstance(cache, dict) else None
    if not isinstance(provider_servers, dict):
        return {}

    candidates = {}
    for by_fingerprint in _provider_cache_entries_for_user(
        provider_servers
    ):
        for stable_fingerprint, observations in by_fingerprint.items():
            if (
                not isinstance(stable_fingerprint, str)
                or not stable_fingerprint.startswith(VSCODE_PROVIDER_PREFIX)
                or not isinstance(observations, list)
            ):
                continue
            for observation in observations:
                validated = _validated_provider_cache_observation(
                    stable_fingerprint,
                    observation,
                )
                if validated is None:
                    continue
                name, config = validated
                normalized_name = name.casefold()
                candidates.setdefault(normalized_name, []).append(
                    (stable_fingerprint, name, config)
                )

    resolved = {}
    for same_name in candidates.values():
        fingerprints = {candidate[0] for candidate in same_name}
        # One runtime name claiming multiple validated provider identities is
        # ambiguous. Keep the name present with a null config so the existing
        # resolver cannot silently borrow either identity.
        if len(fingerprints) != 1:
            chosen_name = min(candidate[1] for candidate in same_name)
            resolved[chosen_name] = None
            continue

        # Multiple ports for one stable provider are expected. Pick one config
        # deterministically; the fingerprint is port-independent, while every
        # observation remains intact in the cache file.
        _fingerprint, chosen_name, chosen_config = min(
            same_name,
            key=lambda candidate: (
                candidate[1].casefold(),
                candidate[1],
                candidate[2]['url'],
                candidate[2]['additional_data']['providerId'],
                candidate[2]['additional_data']['providerServerId'],
            ),
        )
        resolved[chosen_name] = chosen_config
    return resolved


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
    return _read_copilot_mcp_servers_with_sources(cwd)[0]


def _read_copilot_mcp_servers_with_sources(cwd=None):
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
    cached_providers = _copilot_provider_servers_from_cache(_read_mcp_tools_cache())
    cached_by_name = {
        name.casefold(): (name, config)
        for name, config in cached_providers.items()
    }
    existing_names = {name.casefold(): name for name in servers}
    for provider_name, provider_config in cached_providers.items():
        normalized_name = provider_name.casefold()
        existing_name = existing_names.get(normalized_name)
        if existing_name is None:
            servers[provider_name] = provider_config
            server_sources[provider_name] = 'validated-provider'
            existing_names[normalized_name] = provider_name
            continue
        if servers.get(existing_name) != provider_config:
            servers[existing_name] = None
            ambiguous_names.add(existing_name)

    for name, fields in _vscode_cached_mcp_servers(cwd):
        normalized_name = name.casefold()
        validated_provider = cached_by_name.get(normalized_name)
        existing_name = existing_names.get(normalized_name, name)
        if existing_name in ambiguous_names:
            continue
        if validated_provider is not None:
            _provider_name, provider_config = validated_provider
            if (
                _mcp_provider_identity(fields)
                != _mcp_provider_identity(provider_config)
            ):
                servers[existing_name] = None
                ambiguous_names.add(existing_name)
            continue
        if name in server_sources:
            existing = servers.get(name)
            existing_provider = _mcp_provider_identity(existing)
            incoming_provider = _mcp_provider_identity(fields)
            if (
                _mcp_launch_identity(existing) != _mcp_launch_identity(fields)
                or (
                    existing_provider is not None
                    and incoming_provider is not None
                    and existing_provider != incoming_provider
                )
            ):
                servers[name] = None
                ambiguous_names.add(name)
                continue
            servers[name] = {**fields, **existing}
        else:
            servers[name] = fields
            server_sources[name] = 'provider'
    return servers, server_sources, ambiguous_names


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

    # 3x20s exceeds the cloud timeoutSec, and a preToolUse killed by it fails OPEN.
    attempts, per_attempt = (2, 8) if RUNNING_CLOUD else (3, 20)

    for attempt in range(attempts):
        try:
            result = subprocess.run(
                _curl_base() + ["-fsSL", "-X", "POST",
                 "-H", f"Authorization: Bearer {api_key}",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data.encode(),
                capture_output=True,
                timeout=per_attempt
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

        if attempt < attempts - 1:
            time.sleep(0.5)

    return {}


_APPROVAL_MARKER_FILE = LOG_DIR / ".approval_pending"


def _is_approval_retry(command):
    """True if a marker exists for this exact command and is fresh."""
    # No approver in a sandbox, and the marker sits in agent-writable /tmp: a planted one
    # starts a poll that outlives the timeout, and the kill fails open.
    if RUNNING_CLOUD:
        return False
    try:
        if not _APPROVAL_MARKER_FILE.exists():
            return False
        data = json.loads(_APPROVAL_MARKER_FILE.read_text())
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        return data.get('cmd') == cmd_hash and (time.time() - data.get('ts', 0)) < APPROVAL_TIMEOUT
    except (OSError, json.JSONDecodeError):
        return False


def _set_approval_marker(command, policy_ids, application_id, request_id='', unbound_trace_id=''):
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
        'requestId': request_id,
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
                    _curl_base() + ["-fsSL", "-X", "POST",
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

    # Nobody answers an 'ask' in a sandbox, and GitHub does not document it as fail-closed
    # for a non-interactive session, so returning one risks the call simply proceeding.
    if RUNNING_CLOUD and decision == 'ask':
        decision = 'deny'
        additional_context = (additional_context + ' ' if additional_context else '') + (
            'This needed human approval and a cloud agent session has no one to ask. '
            'Do not retry or work around it. Stop and say so in the pull request.')

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
    # The attribution footer must be the last thing the user reads, after the context.
    reason, footer = _split_attribution_footer(reason, api_response.get('unbound_trace_id'))
    model_reason = ' '.join(part for part in (reason, additional_context) if part) + footer
    return {
        'permissionDecision': decision,
        'permissionDecisionReason': model_reason,
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': decision,
            'permissionDecisionReason': model_reason,
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
    if decision in ('deny', 'block'):
        return {
            'decision': 'block',
            'reason': reason
        }

    additional_context = api_response.get('additionalContext', '')
    if additional_context:
        return {'additionalContext': additional_context}

    return {}


# The cloud agent sends no event-name field at all, so the loader passes the registered
# name through and it is mapped onto the names main() dispatches on.
CLOUD_EVENT_NAMES = {
    'sessionStart': 'SessionStart',
    'userPromptSubmitted': 'UserPromptSubmit',
    'preToolUse': 'PreToolUse',
    'postToolUse': 'PostToolUse',
    'agentStop': 'Stop',
    'sessionEnd': 'SessionEnd',
}


def _normalize_cloud_event(event, event_name):
    """Give a cloud payload the field names every audit-log reader matches on.

    The rows are written to the audit log as they arrive, and the cloud agent sends no
    hook_event_name at all and camelCases the rest. Left raw, the turn-start, prompt,
    session-model and previous-Stop lookups all match nothing — and a Stop with no floor
    reports the session's whole usage as that turn's.
    """
    if not RUNNING_CLOUD or not isinstance(event, dict):
        return event
    filled = {}
    if event_name and not event.get('hook_event_name'):
        filled['hook_event_name'] = event_name
    for snake, camel in (('session_id', 'sessionId'), ('transcript_path', 'transcriptPath')):
        value = event.get(camel)
        if not event.get(snake) and value:
            filled[snake] = value
    return dict(event, **filled) if filled else event


def _copilot_event_name(event):
    name = event.get('hook_event_name') or event.get('hookEventName')
    if name:
        return name
    declared = os.environ.get('UNBOUND_HOOK_EVENT')
    if declared:
        return CLOUD_EVENT_NAMES.get(declared, declared)
    # Copilot 1.0.82 omits the event-name field from userPromptTransformed,
    # while still sending both the original and transformed prompt fields.
    if isinstance(event.get('transformedPrompt'), str) and isinstance(event.get('prompt'), str):
        return 'userPromptTransformed'
    return None


def _repo_gate_denial(event):
    """The repo gate's deny response, or None when it allows."""
    gate = _repo_gate_evaluate(event)
    if not gate:
        return None
    return transform_response_for_copilot({
        'decision': 'deny',
        'reason': _repo_gate_block_reason(gate['repo'], gate.get('trace_id')),
        'additionalContext': REPO_GATE_BLOCK_CONTEXT,
        'unbound_trace_id': gate.get('trace_id'),
    })


def process_pre_tool_use(event, api_key):
    """PreToolUse entry point. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for Read/Write/Edit when no policy covers them.

    Not in the sandbox. Nothing survives there from an earlier event, so the gate would run
    with no repo policies at all and allow every repo-scoped write. The evaluator goes
    first instead -- it always reaches the gateway in cloud -- and the gate then runs
    against the policies that answer carried back.
    """
    if RUNNING_CLOUD:
        verdict = _evaluate_pre_tool_use_policies(event, api_key) or {}
        # Only a deny ends it: an 'ask' is truthy without being a stop, and returning early
        # on one would skip the gate for exactly the calls a repo policy exists to block.
        if verdict.get('permissionDecision') == 'deny':
            return verdict
        return _repo_gate_denial(event) or verdict

    denial = _repo_gate_denial(event)
    return denial if denial else _evaluate_pre_tool_use_policies(event, api_key)


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
                _dispatch_mcp_diagnostic(raw_tool, event.get('cwd'), api_key)
        else:
            is_mcp = True
            canonical = f"mcp__{mcp_server}__{mcp_tool}"
            config_scope = (
                (mcp_server_config.get('additional_data') or {}).get('scope')
                if isinstance(mcp_server_config, dict)
                else None
            )
            if (
                config_scope != 'copilot-builtin'
                and config_scope != VSCODE_PROVIDER_CACHE_SCOPE
            ):
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

    # Both come back out of the agent-writable audit log and are sent as the context the
    # gateway judges this call against, so a forged row would be decision input. The
    # gateway already has the real prompts from userPromptSubmitted.
    model = 'auto' if RUNNING_CLOUD else (get_session_start_model(session_id) or 'auto')
    command = extract_command_for_pretool(canonical, tool_input)

    recent_user_prompts = [] if RUNNING_CLOUD else get_recent_user_prompts_for_session(
        session_id, PRETOOL_USER_MESSAGES_LIMIT
    )

    # Preserve the raw event (raw tool_name + tool_input) inside metadata.
    metadata = dict(event)
    _attach_installed_skill_facts(metadata, event)
    file_path = tool_input.get('filePath') or tool_input.get('path') or tool_input.get('file_path')
    if file_path:
        metadata['file_path'] = file_path

    if mcp_server is not None:
        metadata['mcp_server'] = mcp_server
        metadata['mcp_tool'] = mcp_tool
        if mcp_server_config:
            metadata['mcp_server_config'] = _augment_script_hash(
                mcp_server_config, metadata.get('cwd'))
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
            unbound_trace_id = marker_data.get('unboundTraceId')
            footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return {}
            elif result == 'deny':
                return transform_response_for_copilot({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This action was denied via Slack.' + footer,
                    'additionalContext': 'This action was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                    'unbound_trace_id': unbound_trace_id,
                })
            else:
                return transform_response_for_copilot({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry.' + footer,
                    'additionalContext': 'This action was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                    'unbound_trace_id': unbound_trace_id,
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        # Nothing is cached from an earlier event in the sandbox, so the org's setting is
        # unreadable and the default would be 'allow'. Match the loader, which already denies.
        if RUNNING_CLOUD or get_policy_check_failure_action() == 'block':
            footer = _attribution_footer() if get_unbound_attribution_enabled() else ''
            return transform_response_for_copilot({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON + footer,
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
        # No approver, and the retry path polls until the hook is killed — which fails open.
        if RUNNING_CLOUD:
            return transform_response_for_copilot({
                'decision': 'deny',
                'reason': 'Blocked by organization policy. This action requires approval, which a cloud agent cannot obtain.',
                'additionalContext': 'This action requires human approval and a cloud agent session has no approver. Do not retry and do not work around it. Stop and say so in the pull request.',
            })

        approval_check = api_response.get('approvalCheck', {})
        policy_ids = approval_check.get('policyIds', [])
        application_id = approval_check.get('applicationId', '')
        request_id = approval_check.get('requestId', '')
        # The gateway logged this hold under a trace ID; the retry's local verdicts reuse it.
        unbound_trace_id = api_response.get('unbound_trace_id') or ''
        footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, unbound_trace_id=unbound_trace_id)
        return transform_response_for_copilot({
            'decision': 'deny',
            'reason': 'An approval request has been sent to your Slack DMs. Please approve it there.' + footer,
            'unbound_trace_id': unbound_trace_id,
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
        _dispatch_mcp_server_scan(mcp_server, scan_config, cwd=event.get('cwd'))

    if (
        api_response.get('decision') == 'deny'
        and api_response.get('inject_skills')
        and api_response.get('additionalContext')
    ):
        _claim_skill_injection_turn(event)
    _apply_skill_lifecycle_actions(api_response, api_key)
    return transform_response_for_copilot(api_response)


def _evaluate_user_prompt_policy(event, api_key):
    session_id = event.get('session_id') or event.get('sessionId')
    # Read out of the agent-writable audit log and sent as policy context. SessionStart
    # returns before the audit write, so a planted row is the only thing this could find.
    model = 'auto' if RUNNING_CLOUD else (get_session_start_model(session_id) or 'auto')
    prompt = event.get('prompt') or event.get('transformedPrompt') or ''

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    metadata = {}
    cwd = event.get('cwd')
    if isinstance(cwd, str) and cwd:
        metadata['cwd'] = cwd
    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'copilot',
        'model': model,
        'event_name': 'user_prompt',
        'messages': [{'role': 'user', 'content': prompt}] if prompt else [],
        'pre_tool_use_data': {'tool_name': '', 'command': '', 'metadata': metadata},
    }
    _attach_installed_skill_facts(request_body['pre_tool_use_data']['metadata'], event)
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    _apply_skill_lifecycle_actions(api_response, api_key)
    return api_response


def process_user_prompt_submit(event, api_key):
    api_response = _evaluate_user_prompt_policy(event, api_key)
    response = transform_response_for_copilot_prompt(api_response)
    if response.get('additionalContext') and api_response.get('inject_skills'):
        _claim_skill_injection_turn(event)
    return response


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


# The cloud gate runs after the loader's fetch and the gateway's retries, so it inherits
# what is left of the pre-tool budget: 10s put the worst case at 34.5s against a 30s
# timeout, and an overrun is a killed preToolUse, which fails open.
def _git_remote_timeout():
    return 3 if RUNNING_CLOUD else 10


def _git_origin_url(cwd):
    """Origin's URL, else None; raises only if git cannot run, so callers fail open."""
    result = subprocess.run(
        ['git', '-C', cwd, 'remote', 'get-url', 'origin'],
        capture_output=True, text=True, timeout=_git_remote_timeout(),
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


# --- Repository-scope gate: blocks writes, git write subcommands and shell writes in repos outside the org's allowed scope, decided on-device and fail-open ---

# Write tools, git write subcommands and shell writes only; reads, conversation and every other shell command (ls, cat, npm test) are ungated. Names are canonical_tool_name output.
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


def _cloud_gate_violating_repo(block_policies):
    """The session's repo, from the environment rather than from the checkout.

    Reading it back out of `.git/config` hands the answer to the agent: `git remote
    set-url origin <an-allowed-repo>` relabels the session, a corrupt config makes git
    exit non-zero, and an include.path pointing at a FIFO stalls it -- each one ordinary,
    none of them an attack on the hook, and all three end in the write going through.
    GITHUB_REPOSITORY is set before the hook starts and the agent cannot reach it.

    Unresolvable is a deny: a block policy exists and nothing here can say it does not
    apply. Returns the offending slug, or None when the repo is in scope.
    """
    slug = (os.environ.get('GITHUB_REPOSITORY') or '').strip().lower()
    org, _, repo = slug.partition('/')
    if not org or not repo:
        return slug or 'an unidentified repository'
    if any(_repo_gate_scope_allows(p, org, repo) for p in block_policies):
        return None
    return '%s/%s' % (org, repo)


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
        _curl_base() + ['-fsSL', '--max-time', '10', '-X', 'POST',
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

        if RUNNING_CLOUD:
            repo = _cloud_gate_violating_repo(block_policies)
        else:
            candidates = _repo_gate_candidates(
                canonical, tool_input, event.get('cwd'))
            repo = _repo_gate_violating_repo(candidates, block_policies, {})
        gate = {'decision': 'deny', 'repo': repo} if repo else None
        if gate and get_unbound_attribution_enabled():
            gate['trace_id'] = str(uuid.uuid4())
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
    'nohup': ('', set(), 0),
}
# Reserved words that open, divide or close a compound command.
_TRANSFER_KEYWORDS = frozenset({'{', '}', 'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'for', 'select', 'do',
                                'done', '!', 'function'})
# Reserved words after which the next word still starts a command.
_TRANSFER_LEADING_WORDS = frozenset({'{', 'if', 'then', 'elif', 'else', 'while', 'until', 'do', '!'})
_TRANSFER_LOOPS = ('while', 'until', 'for', 'select')
_TRANSFER_DECLARES = ('declare', 'typeset', 'local', 'readonly')
_TRANSFER_SHELLS = frozenset({'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash'})
_TRANSFER_POWERSHELLS = frozenset({'powershell', 'pwsh'})
# Set in a command's env by `env -i`: nothing is inherited from the hook's environment.
_TRANSFER_CLEAN_ENV = '\0clean'
# Stands in for a substitution's output inside a word, so no host is read from it.
_TRANSFER_SUBSTITUTED = '\0'
# Mark a word's unquoted { , and }, which bash may brace-expand, and turn them back once it has.
_TRANSFER_BRACE_MARKS = {'{': '\1', ',': '\2', '}': '\3'}
_TRANSFER_UNMARK = {1: '{', 2: ',', 3: '}'}
_TRANSFER_TOOLS = {
    'curl': 'curl', 'wget': 'wget', 'scp': 'scp', 'rsync': 'rsync', 'sftp': 'sftp', 'ssh': 'ssh',
    'nc': 'nc', 'ncat': 'nc', 'netcat': 'nc', 'socat': 'socat', 'http': 'httpie', 'https': 'httpie',
    'invoke-webrequest': 'powershell', 'invoke-restmethod': 'powershell', 'iwr': 'powershell', 'irm': 'powershell',
}
_TRANSFER_SENDING_METHODS = frozenset({'POST', 'PUT', 'PATCH'})
# The port a URL connects to when it names none, by scheme.
_TRANSFER_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990, 'ws': 80, 'wss': 443}
# Options that take a value, per program; every other option is a switch.
_TRANSFER_SSH_VALUE_FLAGS = {'ssh': frozenset('BbcDEeFIiJLlmOoPpQRSWw'), 'scp': frozenset('cDFiJloPSX'),
                             'sftp': frozenset('BbcDFiJloPRSsX'), 'rsync': frozenset('efTMB@')}
# Of ssh's -o settings, only these change which host or user ssh -G resolves.
_TRANSFER_SSH_IDENTITY_OPTIONS = frozenset({'hostname', 'user', 'port', 'proxyjump'})
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
    """Run one allowlisted lookup within its timeout and the turn's budget; None when refused, slow or failing."""
    try:
        if not any(tuple(argv[:len(p)]) == p for p in _TRANSFER_ALLOWED_RUNS):
            return None
        remaining = _transfer_deadline(state) - time.monotonic()
        if remaining <= 0:
            return None
        result = subprocess.run(argv, cwd=cwd if cwd and os.path.isdir(cwd) else None, capture_output=True,
                                text=True, timeout=min(_TRANSFER_RUN_TIMEOUT, remaining), stdin=subprocess.DEVNULL)
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


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


def _transfer_paren_end(text: str, i: int) -> int:
    """The index of the ) that closes a ( just before i, past quotes and nested parentheses; -1 when none does."""
    depth, quote = 1, None
    while i < len(text):
        ch = text[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == '\\':
            i += 1
        elif quote == '"':
            if ch == '"':
                quote = None
            elif text.startswith('$(', i):
                i = _transfer_paren_end(text, i + 2)
                if i < 0:
                    return -1
        elif ch in '\'"':
            quote = ch
        elif ch in '()':
            depth += 1 if ch == '(' else -1
            if depth == 0:
                return i
        i += 1
    return -1


def _transfer_backtick_end(text: str, i: int) -> int:
    """The index of the backtick that closes one just before i; -1 when none does."""
    while i < len(text):
        if text[i] == '`':
            return i
        i += 2 if text[i] == '\\' else 1
    return -1


class _TransferLexer:
    """Reads a command the way the shell does into items, in the order they run: ('cmd', argv, operator before,
    operator after, redirections) for each simple command, and ('(' | '$(' | ')' | 'func' | 'case' | 'arm' | 'esac',
    None or [function name], operator before, '', None) around subshells, substitutions, function bodies and case
    arms. Redirections are kept in the order written, each as (fd, 'file' | 'null' | the fd it copies): a file or
    heredoc is read or written, /dev/null or a closed fd moves no data."""

    def __init__(self, text: str, depth: int = 0):
        self.text, self.depth, self.i, self.quote = text, depth, 0, None
        self.items, self.argv, self.word, self.in_word = [], [], '', False
        self.before, self.io, self.heredocs, self.case = '', [], [], []
        self.param, self.dollar = 0, -1

    def read(self) -> Optional[List[tuple]]:
        """The items, or None when the command can't be read the way the shell reads it."""
        if self.depth > _TRANSFER_MAX_DEPTH:
            return None
        while self.i < len(self.text):
            if not (self._quoted() if self.quote else self._unquoted()):
                return None
            self.i += 1
        if self.quote:
            return None
        self._end_command('')
        return self.items

    def _quoted(self) -> bool:
        ch = self.text[self.i]
        if ch == self.quote:
            self.quote = None
        elif self.quote == '"' and ch in '$`':
            found = self._substitution()
            if found is not None:
                return found
            self.word += ch
        elif self.quote == '"' and ch == '\\' and self.i + 1 < len(self.text):
            self.i += 1
            self.word += self.text[self.i]
        else:
            self.word += ch
        return True

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
            self.word, self.in_word = self.word + text[self.i], True
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
        if text.startswith('$((', i):
            end = _transfer_paren_end(text, i + 2)  # arithmetic runs no commands
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
        head = self.argv[:-1] if self.argv[-1:] == ['for'] else self.argv
        end = _transfer_paren_end(self.text, self.i + 1) if self.text.startswith('((', self.i) else -1
        if end > 0 and not self.in_word and all(w in _TRANSFER_LEADING_WORDS for w in head):
            # An arithmetic command, or a for loop's (( )) header, is one word that runs nothing.
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
        if op in ('<<', '<<-'):
            self.heredocs.append((target, op == '<<-'))
        to = fd if fd is not None else 0 if op[0] == '<' else 1
        if op in ('<&', '>&') and (target.isdigit() or target == '-'):
            self.io.append((to, int(target) if target.isdigit() else 'null'))
        else:
            # A heredoc or here-string feeds its text.
            self.io.append((to, 'null' if target == '/dev/null' and op not in ('<<', '<<-', '<<<') else 'file'))
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
        """A heredoc's body starts on the next line and is input, not commands."""
        text = self.text
        while self.heredocs:
            delimiter, strip_tabs = self.heredocs.pop(0)
            while self.i + 1 < len(text):
                end = text.find('\n', self.i + 1)
                line = text[self.i + 1:] if end < 0 else text[self.i + 1:end]
                self.i = len(text) - 1 if end < 0 else end
                if (line.lstrip('\t') if strip_tabs else line) == delimiter:
                    break

    def _end_word(self) -> None:
        if not self.in_word:
            return
        marked, state = self.word, self.case[-1] if self.case else None
        self.word, self.in_word, self.param, self.dollar = '', False, 0, -1
        word = marked.translate(_TRANSFER_UNMARK)
        at_start = all(w in _TRANSFER_LEADING_WORDS for w in self.argv)
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
    """A variable as the command sees it: set or unset in the command, else inherited from the hook's environment."""
    if key in env:
        return env[key]
    return '' if _TRANSFER_CLEAN_ENV in env else os.environ.get(key, '')


def _transfer_is_assignment(token: str) -> bool:
    """NAME=value, or NAME+=value, which appends to the value."""
    name = token.split('=', 1)[0]
    name = name[:-1] if name.endswith('+') else name
    return '=' in token and not token.startswith('-') and name.replace('_', '').isalnum()


def _transfer_appends(words: List[str], shell: Dict) -> List[str]:
    """The words with each leading NAME+=value made NAME=value. In a command of only assignments the value is appended
    to the one an earlier word or else the shell gives the name; before a command it is unknown, since bash 3 appends
    it to nothing there while bash 5 and zsh append it to that value."""
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
    """(program, its args, inline VAR=value settings, folder it runs in, whether it runs as another user)."""
    env, argv, i, wrapper, operands, options_done, other_user = {}, list(argv), 0, None, 0, False, False
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
                return None, [], env, cwd, other_user  # only looks the command up
            i, cwd = _transfer_wrapper_option(wrapper, token, argv, i, env, cwd)
            continue
        if wrapper is not None and operands > 0:
            operands -= 1
            continue
        if _transfer_program_name(token) in _TRANSFER_WRAPPERS:
            wrapper, options_done = _transfer_program_name(token), False
            operands = _TRANSFER_WRAPPERS[wrapper][2]
            other_user = other_user or wrapper in ('sudo', 'doas')
            continue
        return _transfer_program_name(token), argv[i:], env, cwd, other_user
    return None, [], env, cwd, other_user


def _transfer_cd(args: List[str], cwd: Optional[str]) -> Optional[str]:
    """The folder a cd with args lands in from cwd: cwd when no shell takes one of its options, and None when bash 3,
    bash 5 and zsh land in different places or the folder is not known."""
    folders, letters = list(args), ''
    while folders and folders[0].startswith('-') and folders[0] != '-':
        option = folders.pop(0)
        if option == '--':
            break
        letters += option[1:]
    if any(c not in 'LPeqs@0123456789' for c in letters):
        return cwd  # every shell rejects the cd and stays
    if len(folders) > 1 or any(c not in 'LP' for c in letters):
        return None  # bash 5 rejects a second folder, bash 3 ignores it and zsh substitutes it; -e, -q, -s, -@ vary
    # Bash follows the last of -L and -P, zsh any -P; -P resolves each link, so a later `cd ..` leaves the real folder.
    last = letters[max(letters.rfind('L'), letters.rfind('P'))] if letters else 'L'
    path = folders[0] if folders else '~'
    landed = {_transfer_move(cwd, path, physical) for physical in {last == 'P', 'P' in letters}}
    return landed.pop() if len(landed) == 1 else None


def _transfer_move(cwd: Optional[str], path: str, physical: bool) -> Optional[str]:
    """The folder a cd to path lands in from cwd, with its links resolved when physical; None when that hangs on a
    folder not known or on `cd -`, or the folder is not there now, so the cd may have failed and left the shell where
    it was."""
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
    inherited = _TRANSFER_CLEAN_ENV not in shell['vars'] and name in os.environ
    return (os.environ[name] if inherited else None), inherited


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
    frames.append({'kind': kind, 'base': runs, 'runs': runs, 'rel': True, 'alive': True, 'decided': False,
                   'saved': None, 'state': _transfer_snapshot(shell), 'status': shell['status'],
                   'calls': len(shell['calls']), 'piped_in': shell.pop('opening_pipe', False),
                   'piped_out': _transfer_ends_piped(head, shell),
                   'outer': (shell['pipe'], shell['start']), 'defines': name, 'head': (shell['at'], head),
                   'iterates': None, 'repeats': False, 'left': None, 'doubt': _transfer_doubt(shell['pipe']),
                   'jumped': None,
                   'unsure': set(), 'outside': _transfer_liveness(shell)})
    shell['start'] = _transfer_snapshot(shell)  # the body starts a list of its own
    _transfer_pipeline('', runs, shell)


def _transfer_status(frame: Dict, status: Optional[int]) -> Optional[int]:
    """The status a closed compound leaves, given its last command's: a function definition succeeds, a compound that
    never ran keeps the one before it, an if or loop that ran no body succeeds, a body that may have run leaves it
    unknown, and one a return, exit, break or continue ended leaves that one's."""
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
    """At a compound's end, make unknown what may not have happened: a body that may not have run, what followed a
    return, exit, break or continue that may have run, and all of it when the compound was reached only through an
    && or || after an unknown status, or is a loop that may run its body again."""
    for since in (frame['jumped'], frame['state'] if frame['doubt'] or frame['repeats'] else None):
        if since:
            frame['unsure'] |= _transfer_changes(shell, since)
    _transfer_leave(frame, shell)
    _transfer_forget(shell, frame['unsure'])


def _transfer_wrap(shell: Dict, first: int, layer: tuple) -> None:
    """Wrap each call from first on in one more level of (piped in, piped out, redirections)."""
    calls = shell['calls']
    for i in range(first, len(calls)):
        calls[i] = calls[i][:5] + (calls[i][5] + (layer,),)


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
    """Wrap the commands inside a closed compound in the pipes and redirections around it; a piped or backgrounded
    compound runs in a subshell, so its cd, exports, functions and any exit inside it end with it."""
    _transfer_wrap(shell, frame['calls'], layer)
    if layer[0] or layer[1] or background:
        _transfer_restore(shell, frame['state'], True)
        _transfer_revive(frame['outside'], shell)


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


def _transfer_keyword(words: List[str], item: tuple, shell: Dict) -> List[str]:
    """Apply a command's leading reserved word to the open compound commands and its pipeline; the words after it."""
    keyword, rest, frames = words[0], words[1:], shell['frames']
    if keyword in ('{', 'if') + _TRANSFER_LOOPS:
        _transfer_open(keyword, shell['pipe']['runs'], shell, ('cmd', words, '', item[3], item[4]))
        if keyword in _TRANSFER_LOOPS:
            frames[-1]['iterates'], frames[-1]['repeats'] = _transfer_loop(keyword, rest, shell)
        return [] if keyword in ('for', 'select') else rest  # a for loop's header runs nothing
    if keyword in ('!', 'function'):
        # `!` flips the status of the whole pipeline it leads, a compound included, and a second one flips it back.
        if keyword == 'function':
            shell['function'], rest = (rest[0] if rest else ''), rest[1:]
        else:
            shell['pipe']['negate'] = not shell['pipe']['negate']
        shell['pipe']['leading'] = True
        return rest
    if keyword in ('}', 'fi', 'done'):
        frame = _transfer_pop(frames, {'}': ('{',), 'fi': ('if',), 'done': _TRANSFER_LOOPS}[keyword])
        if frame:
            _transfer_doubtful(frame, shell)
            _transfer_settle(frame, ('cmd', [keyword], item[2], '', item[4]), shell)
        shell['closed'] = frame
        return rest
    if frames:
        _transfer_branch(keyword, frames[-1], shell)
    _transfer_pipeline('', _transfer_runs(shell), shell)
    return rest


def _transfer_loop(keyword: str, rest: List[str], shell: Dict) -> tuple:
    """(whether a loop runs its body once at least: True, False, or None when not known; whether it may run it again).
    A literal word runs a for body at least once, and a list with no words never runs a for or select body; without
    `in` the list is the positional parameters. Any loop but a for over one plain word may run its body again."""
    if keyword == 'for' and rest[:1] and rest[0].startswith('(('):
        return _transfer_counted(rest[0]), True
    if keyword not in ('for', 'select'):
        return None, True
    listed = rest[2:] if rest[1:2] == ['in'] else shell['args']
    literal = keyword == 'for' and any('$' not in w and _TRANSFER_SUBSTITUTED not in w for w in listed or [])
    plain = listed is not None and len(listed) == 1 and not any(c in listed[0] for c in '$*?[\0')
    return True if literal else False if listed == [] else None, keyword != 'for' or not plain


def _transfer_counted(word: str) -> Optional[bool]:
    """Whether an arithmetic for runs its body once at least, from its first test: known when there is none, or when
    it compares the counter the loop starts at a number with another number; None for anything else."""
    parts = word[2:-2].split(';') if word.endswith('))') else []
    if len(parts) != 3:
        return None
    start = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0|[1-9][0-9]*)\s*', parts[0])
    test = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*(0|[1-9][0-9]*)\s*', parts[1])
    if parts[0].strip() and not start:
        return None
    if not parts[1].strip():
        return True  # no test runs it until a break
    if not (start and test and start.group(1) == test.group(1)):
        return None
    a, op, b = int(start.group(2)), test.group(2), int(test.group(3))
    return {'<': a < b, '<=': a <= b, '>': a > b, '>=': a >= b, '==': a == b, '!=': a != b}[op]


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


def _transfer_builtin(program: str, args: List[str], cwd: Optional[str], shell: Dict) -> None:
    """Apply a cd, export, unset or declaration, or a command made only of assignments (program ''), to the commands
    after it."""
    if program == 'cd':
        shell['cwd'] = _transfer_cd(args, cwd)
    elif program == 'unset':
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
    """unset -f removes functions, and -v or a bare name variables; a variable gone takes its export, so the hook's own
    value is gone too. A bare name with no variable set removes the function in bash but not in zsh, so the function
    then may or may not be there, as is one removed by an unset -f that may not run."""
    sure = shell['pipe']['runs'] is True and not _transfer_doubt(shell['pipe'])
    for name in (a for a in args if not a.startswith('-')):
        value = _transfer_variable(shell, name)[0]
        known = shell['functions'].get(name)
        if '-f' not in args:
            shell['vars'][name] = (None, False)
        if known and ('-f' in args or ('-v' not in args and (value is None or _TRANSFER_SUBSTITUTED in value))):
            if sure and '-f' in args:
                del shell['functions'][name]
            else:
                shell['functions'][name] = known[0], True


def _transfer_declare(program: str, args: List[str], shell: Dict) -> None:
    """declare or typeset outside a function sets each NAME=value, exports it with -x and stops that with +x, as export
    does. Any other option, a +=, local, readonly, and a declaration inside a function, which bash keeps to the function
    and zsh may not, leave the names unknown."""
    on = off = ''
    while args and args[0][:1] in '-+' and len(args[0]) > 1:
        option, args = args[0], args[1:]
        if option == '--':
            break
        on, off = (on + option[1:], off) if option[0] == '-' else (on, off + option[1:])
    plain = program in ('declare', 'typeset') and shell['floor'] is None and set(on + off) <= {'x'} and not (on and off)
    for name, eq, value in (arg.partition('=') for arg in args):
        if not plain or name.endswith('+'):
            _transfer_forget(shell, {name.rstrip('+')} - {''})
            continue
        current, exported = _transfer_variable(shell, name)
        shell['vars'][name] = (value if eq else current, True if on else False if off else exported)


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
                return ' '.join(args[i + 1:])
    return None


def _transfer_call(known: tuple, layer: tuple, subshell: bool, shell: Dict, depth: int) -> None:
    """Run a defined function's body, from known (body, whether it may not have been defined), where it is called: in
    this shell with the call's stdin and stdout, or in a subshell when the call is piped or backgrounded. A call reached
    only through an && or || after an unknown status, or to a function that may not exist, leaves what it changed
    unknown."""
    body, maybe = known
    if depth >= _TRANSFER_MAX_DEPTH or shell['calls_left'] <= 0:
        shell['status'] = None
        return
    shell['calls_left'] -= 1
    first, state = len(shell['calls']), _transfer_snapshot(shell)
    outer, outside = (shell['pipe'], shell['start'], shell['floor']), _transfer_liveness(shell)
    shell['floor'] = len(shell['frames'])
    _transfer_items(body, shell, depth + 1)
    shell['pipe'], shell['start'], shell['floor'] = outer
    _transfer_wrap(shell, first, layer)
    if subshell:
        _transfer_restore(shell, state, True)
        _transfer_revive(outside, shell)
    elif maybe or _transfer_doubt(shell['pipe']):
        _transfer_forget(shell, _transfer_changes(shell, state))
        _transfer_soften(outside, shell)
        # A function the body removed may still be there.
        shell['functions'].update((name, (known[0], True)) for name, known in state[2].items()
                                  if name not in shell['functions'])


def _transfer_simple(words: List[str], before: str, after: str, io: list, shell: Dict, depth: int) -> List[tuple]:
    """The calls one simple command makes, after applying its cd, export, unset or declaration; a defined function runs
    its body with the command's words as its positional parameters."""
    layer = (before == '|', after == '|', tuple(io))
    substituted, words = any(_TRANSFER_SUBSTITUTED in w for w in words), _transfer_appends(words, shell)
    name = next((w for w in words if not _transfer_is_assignment(w)), None)
    # A piped or backgrounded command runs in a subshell.
    subshell = before == '|' or after in ('|', '&')
    if name in shell['functions']:
        outer, shell['args'] = shell['args'], words[words.index(name) + 1:]
        _transfer_call(shell['functions'][name], layer, subshell, shell, depth)
        shell['args'] = outer
        if not shell['functions'][name][1]:
            return []
        # A function that may not have been defined may leave the name to the program.
    program, args, env, cwd, other_user = _transfer_program(words, shell['cwd'])
    env = env if _TRANSFER_CLEAN_ENV in env else {**_transfer_exported(shell), **env}
    # A command of nothing but assignments sets them in the shell, and succeeds unless a substitution in it fails.
    assigns = program is None and all(_transfer_is_assignment(w) for w in words)
    status = shell['status']
    shell['status'] = 0 if program in ('true', ':', 'break', 'continue') else 1 if program == 'false' else \
        _transfer_arithmetic(words[0]) if len(words) == 1 else None
    if assigns and not substituted:
        shell['status'] = 0
    if program in ('set', 'shift'):
        shell['args'] = None  # the positional parameters may have changed
    if program in ('return', 'exit'):
        # Either leaves the status it is given, or else the one before it; a return outside a function fails.
        shell['status'] = status if not args else int(int(args[0]) % 256 > 0) if args[0].isdigit() else None
        if program == 'return' and shell['floor'] is None:
            shell['status'] = 1
    if program in ('return', 'exit', 'break', 'continue') and not subshell:
        _transfer_jump(program, args, shell)
    if program in ('cd', 'export', 'unset') + _TRANSFER_DECLARES or assigns:
        # A pipeline's commands run in subshells, so their cd and variables end with them.
        if before != '|' and after != '|':
            saved = _transfer_snapshot(shell)
            _transfer_builtin(program or '', words if assigns else args, cwd, shell)
            if _transfer_doubt(shell['pipe']):
                _transfer_forget(shell, _transfer_changes(shell, saved))  # it may not have run
        return []
    inner = _transfer_shell_string(program, args) if program else None
    if inner is not None:
        # The string's commands run as the wrapper's user and read its stdin and write its stdout.
        # Its words after the string are $0 and then the positional parameters.
        positional = args[args.index(inner) + 2:] if program in _TRANSFER_SHELLS else []
        calls = _transfer_walk(_TransferLexer(inner, depth + 1).read() or [], cwd, env, depth + 1, positional)
        return [call[:4] + (call[4] or other_user, call[5] + (layer,)) for call in calls]
    return [(program, args, env, cwd, other_user, (layer,))] if program else []


def _transfer_command(item: tuple, shell: Dict, depth: int) -> List[tuple]:
    """The calls one simple command makes, if it runs or may run, after the reserved words that lead it."""
    _, words, before, after, io = item
    if words[0] not in ('}', 'fi', 'done'):
        _transfer_begin(before, shell)
    shell['opening_pipe'] = before == '|'
    while words and words[0] in _TRANSFER_KEYWORDS:
        # A body's first command is reached by its compound's pipe, which its own redirections then override.
        before = before if words[0] in ('!', 'function') else ''
        words = _transfer_keyword(words, item, shell)
    shell.pop('opening_pipe', None)
    closed = shell.pop('closed', None)
    if closed:
        _transfer_close(closed, (closed['piped_in'], after == '|', tuple(io)), shell, after == '&')
    calls = []
    if words:
        shell['pipe']['leading'] = False
        if shell['pipe']['runs'] is not False:
            calls = _transfer_simple(words, before, after, io, shell, depth)
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
    """What follows the end of each compound in items, by where it opens (item, word): one piped or backgrounded at
    its end runs in a subshell, which a return, exit, break or continue inside it does not leave."""
    ends, opened = {}, []
    for at, (kind, words, _, after, _) in enumerate(items):
        if kind in ('(', '$(', 'case'):
            opened.append((at, 0))
        elif kind in (')', 'esac') and opened:
            ends[opened.pop()] = after
        k = 0
        while kind == 'cmd' and k < len(words) and words[k] in _TRANSFER_KEYWORDS:
            if words[k] in ('}', 'fi', 'done') and opened:
                ends[opened.pop()] = after if k == len(words) - 1 else ''
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
    return shell['ends'].get((shell['at'], k)) in ('|', '&')


def _transfer_walk(items: List[tuple], cwd: Optional[str], exported: Dict, depth: int,
                   positional: List[str] = ()) -> List[tuple]:
    """Each simple command that runs or may run, as (program, args, env, folder, as another user, the (piped in,
    piped out, redirections) around it from its own outward); commands a literal true or false skips, untaken
    branches and function bodies are left out, and a function's body runs where it is called."""
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
             'items': items, 'at': 0, 'live': True, 'floor': None, 'args': list(positional), 'ends': {}}
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


def _transfer_url_host(url: str) -> str:
    """The host a URL names, with any login, port and path dropped; empty when it names none."""
    from urllib.parse import urlsplit
    try:
        text = url.strip()
        parts = urlsplit(text if '://' in text else 'http://' + text)
        host = parts.hostname or ''
        if '[' in parts.netloc and not _transfer_ip(host):
            return ''  # brackets hold nothing but an IPv6 address, which older Pythons do not check
        if host.isascii():
            return host
        import unicodedata
        # curl (libidn2) and the URL standard dial each non-ASCII label in punycode, keeping ß and a final sigma.
        return '.'.join(label if label.isascii() else 'xn--' + label.encode('punycode').decode('ascii')
                        for label in unicodedata.normalize('NFC', host).split('.'))
    except ValueError:
        return ''


def _transfer_curl(args: List[str]) -> List[tuple]:
    """curl's URLs: sent to when their request uploads a file, a form or a body, or uses a sending method; else fetched
    from. Each --next starts a request with options of its own, though the addresses --resolve pins carry on to the
    requests after it. A URL's {a,b} and [1-3] globs reach every host they name unless --globoff is given, and curl
    stops at a URL whose glob it rejects."""
    endpoints, pins, i = [], [], 0
    while True:
        urls, sends, overrides, globoff, i = _transfer_curl_request(args, i)
        pins += [value for option, value in overrides if option == '--resolve']
        connects = [value for option, value in overrides if option == '--connect-to']
        for url in urls:
            expanded = [url] if globoff else _transfer_curl_glob(url)
            if expanded is None:
                return endpoints
            endpoints += [('out' if sends else 'in', _transfer_url_host(one), None,
                           _transfer_curl_dial(one, connects, pins)) for one in expanded]
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
    """(the host a URL's request connects to, the addresses pinned for it) when --connect-to or --resolve change where
    it connects, as curl applies them: the first --connect-to rule that matches, then the last pin for that host and
    port, a named host before *; None when neither applies."""
    from urllib.parse import urlsplit
    host = _transfer_url_host(url)
    try:
        parts = urlsplit(url.strip() if '://' in url else 'http://' + url.strip())
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
    """(the URLs of the curl request starting at args[i], whether it sends data, its --resolve and --connect-to values in
    order, whether it turns globbing off, where the next request starts); a --next that is another option's value does
    not end it."""
    urls, flags, method, overrides = [], set(), '', []
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
        if arg == '--url' and value:
            urls.append(value)
        elif arg in ('-X', '--request') and value:
            method = value.upper()
        elif arg in ('--resolve', '--connect-to') and value:
            overrides.append((arg, value))
    sends = flags & _TRANSFER_CURL_UPLOADS or method in _TRANSFER_SENDING_METHODS or \
        (flags & _TRANSFER_CURL_BODIES and not flags & {'-G', '--get'})
    return urls, bool(sends), overrides, bool(flags & {'-g', '--globoff'}), i


def _transfer_wget(args: List[str]) -> List[tuple]:
    """wget's URLs: sent to when it posts data or a file; else fetched from."""
    urls, flags, i = [], set(), 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg.startswith('--'):
            name, eq, _ = arg.partition('=')
            if not eq and name in _TRANSFER_WGET_LONG_VALUES:
                i += 1
            flags.add(name)
        elif arg.startswith('-') and len(arg) > 1:
            flag, _, i = _transfer_short_option(arg, args, i, _TRANSFER_WGET_SHORT_VALUES, flags)
            flags.add(flag)
        else:
            urls.append(arg)
    direction = 'out' if flags & _TRANSFER_WGET_UPLOADS else 'in'
    return [(direction, _transfer_url_host(url), None) for url in urls]


def _transfer_ssh_args(program: str, args: List[str]) -> tuple:
    """(operands, the options that change which host or user ssh -G resolves) for ssh, scp or sftp."""
    passthrough, operands, i = [], [], 0
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
        flag, value, i = _transfer_short_option(arg, args, i, value_flags, set())
        option = re.split(r'[\s=]', (value or '').strip(), maxsplit=1)[0].lower()
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
    """ssh used as a pipe: sent to when its stdin is fed in, fetched from when its stdout is kept."""
    operands, options = _transfer_ssh_args('ssh', args)
    if not operands:
        return []
    return [(d, operands[0], options) for d, used in (('out', sends), ('in', receives)) if used]


def _transfer_netcat(args: List[str], sends: bool) -> List[tuple]:
    """nc's host: sent to when its stdin is fed in; a listener reaches no host."""
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
    return [('out' if sends else '', positional[0], None)]


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
        match = re.match(r'^(?:(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?|'
                         r'(?:proxy|socks4a?|socks5):[^:,]+):(\[[^\]]+\]|[^:,]+):', address, re.IGNORECASE)
        if match:
            endpoints.append(('out' if sends else '', match.group(1), None))
    return endpoints


def _transfer_httpie_item(item: str) -> bool:
    """Whether an HTTPie request item is data (=, :=, @, =@, :=@) rather than a header (:) or a query (==)."""
    match = re.match(r'^(?:\\.|[^\\=:@])*(:=@|=@|:=|==|=|@|:)', item)
    return bool(match) and match.group(1) not in ('==', ':')


def _transfer_httpie(args: List[str], sends: bool) -> List[tuple]:
    """HTTPie's URL: sent to when the request carries data or a sending method; else fetched from."""
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
    return [('out' if out else 'in', 'localhost' if url.startswith(':') else _transfer_url_host(url), None)]


def _transfer_web_cmdlet(args: List[str], sends: bool) -> List[tuple]:
    """Invoke-WebRequest's or Invoke-RestMethod's URI: sent to with a body, file, form, piped input or sending
    method; else fetched from."""
    uri, out, positional, i = '', sends, [], 0
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
    uri = uri or (positional[0] if positional else '')
    return [('out' if out else 'in', _transfer_url_host(uri), None)] if uri else []


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
        raw = _transfer_curl(args) if tool == 'curl' else _transfer_wget(args)
    elif tool in ('nc', 'socat'):
        raw = _transfer_netcat(args, sends) if tool == 'nc' else _transfer_socat(args, sends)
    elif tool in ('httpie', 'powershell'):
        raw = _transfer_httpie(args, sends) if tool == 'httpie' else _transfer_web_cmdlet(args, sends)
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


def _transfer_ssh_config_runs(lines: List[str], homes: List[str], bases: tuple, pending: List[tuple]) -> bool:
    """Whether config lines could run a command or a DNS lookup in ssh -G; their Includes are queued on pending,
    resolved against every home and folder ssh may use."""
    import glob
    for line in lines:
        words = _transfer_ssh_config_words(line)
        if words is None:
            return True
        if not words:
            continue
        keyword, _, attached = words[0].partition('=')
        # ssh allows `Keyword=value` and `Keyword =value`, so a leading = is only a separator.
        words = [w.lstrip('=') for w in ([attached] if attached else []) + words[1:] if w.lstrip('=')]
        if keyword.lower() == 'match' and _transfer_match_execs(words):
            return True
        if keyword.lower() == 'canonicalizehostname' and words and words[0].lower() in ('yes', 'always'):
            return True
        for pattern in (words if keyword.lower() == 'include' else []):
            if '$' in pattern or '%' in pattern:
                return True  # ssh may expand a variable or token here
            # ssh globs the path, and glob reads a backslash as escaping the next character.
            pattern = re.sub(r'\\(.)', r'\1', pattern)
            if pattern == '~' or pattern.startswith('~/'):
                paths = [home + pattern[1:] for home in homes]
            else:
                paths = [os.path.join(base, os.path.expanduser(pattern)) for base in bases]
            for path in paths:
                pending += [(found, bases) for found in sorted(glob.glob(path))]
    return False


def _transfer_ssh_config_unsafe(passthrough: List[str], cwd: Optional[str]) -> bool:
    """Whether ssh -G could run a command or a DNS lookup while reading its configs, or reads a file this can't check."""
    import stat
    home = _transfer_home()
    # ssh reads ~/.ssh/config from the account's home but expands an Include's ~ and relative path with $HOME.
    homes = list(dict.fromkeys([home, os.path.expanduser('~')]))
    user_bases = tuple(os.path.join(h, '.ssh') for h in homes)
    config = None
    for flag, value in zip(passthrough[::2], passthrough[1::2]):
        if flag == '-F':
            config = os.path.expanduser(value)
    if config == 'none':
        return False
    if config is None:
        # Whichever ssh is on PATH reads its own system config, so every one that exists is checked.
        system = ['/etc/ssh', '/opt/homebrew/etc/ssh', '/usr/local/etc/ssh',
                  os.path.join(os.environ.get('PROGRAMDATA') or '/nonexistent', 'ssh')]
        pending = [(os.path.join(home, '.ssh', 'config'), user_bases)] + \
            [(os.path.join(d, 'ssh_config'), (d,)) for d in system]
    elif os.path.isabs(config) or (cwd and os.path.isdir(cwd)):
        pending = [(os.path.join(cwd or '', config), user_bases)]
    else:
        return True
    seen = set()
    while pending:
        path, bases = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        try:
            info = os.stat(path)
        except FileNotFoundError:
            continue
        except OSError:
            return True
        # Only small regular files are read, so a fifo or a huge file can't hold up the turn.
        if len(seen) > _TRANSFER_SSH_CONFIG_MAX_FILES or not stat.S_ISREG(info.st_mode) or \
                info.st_size > _TRANSFER_SSH_CONFIG_MAX_BYTES:
            return True
        try:
            with open(path, errors='ignore') as handle:
                lines = handle.read().splitlines()
        except OSError:
            return True
        if _transfer_ssh_config_runs(lines, homes, bases, pending):
            return True
    return False


def _transfer_ssh_hostname(destination: str, options: List[str], cwd: Optional[str], state: Dict) -> str:
    """The host ssh connects to for a destination, read from ssh -G; empty when it can't be looked up safely."""
    # The shell expands a leading ~ in an -F path before ssh sees it.
    options = [os.path.expanduser(v) if i and options[i - 1] == '-F' else v for i, v in enumerate(options)]
    key = ('ssh', destination, tuple(options), cwd)
    if key not in state:
        state[key] = ''
        # A destination starting with - would reach ssh -G as an option.
        if not destination.startswith('-') and not _transfer_ssh_config_unsafe(options, cwd):
            target = destination.replace('[', '').replace(']', '')
            out = _transfer_run(['ssh', '-G'] + options + ['--', target], cwd, state) or ''
            names = [line.split(None, 1)[1] for line in out.splitlines() if line.startswith('hostname ')]
            state[key] = _transfer_clean_host(names[0]) if names else ''
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


def _transfer_address(host: str, state: Dict) -> str:
    """The kind of address a host resolves to, looked up once per turn: public when any address is public, else
    the first address's kind; unresolved when the lookup fails or the turn's budget is spent."""
    import ipaddress
    key = ('address', host)
    if key not in state:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            remaining = _transfer_deadline(state) - time.monotonic()
            addresses = _transfer_resolve(host, min(_TRANSFER_DNS_TIMEOUT, remaining)) if remaining > 0 else []
        state[key] = _transfer_address_kind(addresses)
    return state[key]


def _transfer_address_kind(addresses: list) -> str:
    """public when any address is public, else the first address's kind; unresolved when there is none."""
    kinds = [_transfer_kind(a) for a in addresses]
    return 'unresolved' if not kinds else 'public' if 'public' in kinds else kinds[0]


def _transfer_endpoint(raw: tuple, cwd: Optional[str], state: Dict) -> Optional[Dict]:
    """One place a transfer reached, from (direction, destination, ssh -G options or None[, curl's dial]): its host as
    written without any login, the host it connects to, as ssh -G resolves it or curl's --connect-to and --resolve set
    it, and the kind of address that host has."""
    direction, destination, ssh_options = raw[:3]
    dial = raw[3] if len(raw) > 3 else None
    destination = destination.strip()
    host = _transfer_url_host(destination) if '://' in destination else destination.rsplit('@', 1)[-1]
    host = _transfer_clean_host(host)
    if not host:
        return None
    if dial:
        resolved, address = dial[0], _transfer_address_kind(dial[1]) if dial[1] else _transfer_address(dial[0], state)
    else:
        resolved = (_transfer_ssh_hostname(destination, ssh_options, cwd, state) if ssh_options is not None else '') \
            or host
        address = _transfer_address(resolved, state)
    endpoint = {'direction': direction, 'host': host, 'resolved_host': resolved, 'address': address}
    return {k: v for k, v in endpoint.items() if v}


def _transfer(command: Optional[str], cwd: Optional[str], state: Dict) -> Optional[Dict]:
    """Where a shell call's transfers went: the first transfer tool it ran and each place it sent to or fetched
    from; None when it ran no transfer. Never raises, and never takes longer than the turn's budget."""
    try:
        if not isinstance(command, str) or not command.strip():
            return None
        tool, endpoints = None, []
        for program, args, env, call_cwd, other_user, layers in \
                _transfer_walk(_TransferLexer(command).read() or [], cwd, {}, 0):
            found = _transfer_parse(program, args, env, other_user, layers)
            for raw in (found[1] if found else []):
                if len(endpoints) >= _TRANSFER_MAX_ENDPOINTS:
                    break
                endpoint = _transfer_endpoint(raw, call_cwd, state)
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


def map_copilot_tool(name, args, result_content, shell_state=None, root_projects=None,
                     mcp_servers=None, mcp_server_name=None, mcp_tool_name=None, cwd=None):
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
    transfer = None
    if name in SHELL_TOOLS:
        command = args.get('command') or args.get('input') or args.get('text') or ''
        entry = {
            'type': 'afterShellExecution',
            'command': command,
            'output': result_content or '',
        }
        candidates = []
        # Where this call's transfer lookups start; only a cd that surely ran moves it for the next call.
        start_dir = shell_state.setdefault('transfer_dir', shell_state.get('dir'))
        if isinstance(command, str):
            candidates.extend(p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p))
            candidates.extend(_git_path_opt_targets(command, shell_state.get('dir')))
            shell_state['dir'] = _next_shell_dir(command, shell_state.get('dir'))
        if not candidates and shell_state.get('dir'):
            candidates.append(shell_state['dir'])
        project = _project_for_paths(candidates, root_projects)
        # The cloud runner's Stop shares a shorter budget with the gateway post, as its git lookups do.
        transfer = _transfer(command, start_dir,
                             shell_state.setdefault('transfers', {'budget': 3.0} if RUNNING_CLOUD else {}))
        shell_state['transfer_dir'] = _transfer_next_cwd(command, start_dir)
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
                'mcp_server_config': _augment_script_hash(mcp_server_config, cwd),
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
    if transfer:
        mapped['transfer'] = transfer
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
        log_error(
            f"transcript missing: {os.path.basename(transcript_path) if transcript_path else '<none>'}",
            'transcript',
        )
        return None, set(), None, set(), None

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
    except Exception as e:
        log_error(f"transcript unreadable: {type(e).__name__}", 'transcript')
        return None, set(), None, set(), None

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
            if is_autopilot_continuation(data):
                # Never a turn boundary: this is the turn already open being pushed on,
                # and its output belongs to the prompt that started it.
                continue
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
        log_error(f"transcript turn start not found in {len(entries)} entries", 'transcript')
        return None, set(), None, set(), None

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
    # The model that actually served this turn, which names the real one behind an 'auto'
    # pick. The CLI records it per assistant message; VS Code records none here and is
    # resolved from its own journal by the caller instead.
    served_model = None
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
            # Last one wins: one model serves a turn, and the message that finished it is
            # the one that says which. Bounded because a transcript is a local file.
            entry_model = data.get('model')
            if isinstance(entry_model, str) and entry_model.strip():
                served_model = entry_model.strip()[:MAX_MODEL_NAME_CHARS]
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
            call['started'] = entry.get('timestamp')
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
                    shell_state.setdefault('transfer_dir', shell_state.get('dir'))
                    shell_state['dir'] = _next_shell_dir(command, shell_state.get('dir'))
                    shell_state['transfer_dir'] = _transfer_next_cwd(command, shell_state['transfer_dir'])
            continue
        mapped = map_copilot_tool(call['name'], call['arguments'], call['result'],
                                  shell_state=shell_state, root_projects=root_projects,
                                  mcp_servers=mcp_servers,
                                  mcp_server_name=call['mcp_server_name'],
                                  mcp_tool_name=call['mcp_tool_name'],
                                  cwd=cwd)
        # Advance the watermark for EVERY handled call, mapped or not: an internal tool
        # maps to None (nothing to send) but must still be recorded, else a turn of only
        # internal tools is reparsed on every later Stop and never records progress.
        forwarded_now.add(call_id)
        # `is not None` (not truthiness): None means a consciously-dropped internal
        # tool; an empty-but-valid dict should still be appended.
        if mapped is not None:
            if call_id:
                mapped['tool_use_id'] = call_id  # native transcript toolCallId — no synthetic id
            tool_use.append(_with_call_ts(mapped, call.get('started')))

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
        log_error("transcript produced no messages", 'transcript')
        return None, set(), None, set(), None

    return {
        'conversation_id': conversation_id,
        'model': served_model or model or session_start_model or 'auto',
        'messages': messages,
        'cwd': cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the session cwd's repo.
        'project': _get_project(cwd),
        'agent_surface': copilot_surface(transcript_path),
        # No probe in the sandbox: an ephemeral VM's machine-id invents hardware that
        # rotates or collides across sessions. The github block below is the provenance.
        'account_identity': build_account_identity(probe=not RUNNING_CLOUD,
                                                   surface=copilot_surface(transcript_path),
                                                   transcript_path=transcript_path),
        'github': build_github_context(),
    }, forwarded_now, text_sig, turn_prompt_ids, turn_id


# Visual Studio ships no hook surface, so Copilot Chat is read off disk and backfilled.
_VS_ROLE_USER = 0
_VS_ROLE_ASSISTANT = 1
_VS_TEXT_BLOCK = 3
_VS_MAX_SESSION_BYTES = 8 << 20
_VS_MAX_SESSIONS_PER_RUN = 200
# Solution state lives at <solution>/.vs/<name>/copilot-chat/<id>/sessions/<session-guid>.
_VS_SESSION_TAIL = '.vs/*/copilot-chat/*/sessions/*'
# Bounds one log read. KEEP IN SYNC with mdm/setup.py's _backfill_capped_lines.
_VS_MAX_LOG_LINES = 200000
_VS_MAX_LOG_LINE_CHARS = 1 << 20
# Scanned only for each turn's own time and model, which the replayed history does not carry.
_VS_MAX_METADATA_REQUESTS = 200
# Bytes of a chat log one run reads. A log only grows, so the tail is the recent activity.
_VS_MAX_LOG_BYTES = 64 << 20
# Ceiling across all conversations in one log, so many chats cannot exhaust memory.
_VS_MAX_KEPT_REQUESTS = 2000
# NTFS marks junctions and symlinks with it; absent from stat() on other platforms.
_VS_REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
# Bounds container nesting; real transcripts sit well under ten levels.
_VS_MAX_NESTING = 64
# Bounds the walk so a pathological tree cannot stall an MDM install.
_VS_MAX_WALK_DIRS = 20000
# The only source of real usage; turns known only to the .vs store fall back to estimates.
_VS_USAGE_MARKER = 'InputTokenCount'
_VS_LOG_TIME_RE = re.compile(r'^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.\d+ ')
# Links a logged request to its chat. Startup lines carry the key empty, so require a guid.
_VS_SESSION_RE = re.compile(r'SessionId=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
# VS 2026 prepends this synthetic `user` message to every turn; it is not a prompt.
_VS_SYNTHETIC_USER_PREFIX = '# IDESTATE CONTEXT'


def _mp_read_str(buf, pos, size):
    return buf[pos:pos + size].decode('utf-8', 'replace'), pos + size


def _mp_read_array(buf, pos, size, depth):
    out = []
    for _ in range(size):
        value, pos = _mp_read(buf, pos, depth)
        out.append(value)
    return out, pos


def _mp_read_map(buf, pos, size, depth):
    out = {}
    for _ in range(size):
        key, pos = _mp_read(buf, pos, depth)
        value, pos = _mp_read(buf, pos, depth)
        out[key if isinstance(key, str) else str(key)] = value
    return out, pos


def _mp_timestamp(payload):
    """MessagePack's -1 extension as epoch seconds; VS stamps messages with it."""
    if len(payload) == 4:
        return float(int.from_bytes(payload, 'big'))
    if len(payload) == 8:
        packed = int.from_bytes(payload, 'big')
        return (packed & 0x3FFFFFFFF) + ((packed >> 34) / 1e9)
    if len(payload) == 12:
        return int.from_bytes(payload[4:], 'big', signed=True) + int.from_bytes(payload[:4], 'big') / 1e9
    return None


def _mp_read_ext(buf, pos, size):
    ext_type = int.from_bytes(buf[pos:pos + 1], 'big', signed=True)
    pos += 1
    payload = buf[pos:pos + size]
    pos += size
    return (_mp_timestamp(payload) if ext_type == -1 else None), pos


def _mp_read(buf, pos, depth=0):
    """One MessagePack value as (value, next_pos). Visual Studio writes its chat store in it."""
    # Nested containers recurse, so a file of repeated 0x91 would exhaust the stack.
    if depth > _VS_MAX_NESTING:
        raise ValueError('messagepack nesting deeper than %d' % _VS_MAX_NESTING)
    code = buf[pos]
    pos += 1
    if code <= 0x7F:
        return code, pos
    if code >= 0xE0:
        return code - 0x100, pos
    if 0x80 <= code <= 0x8F:
        return _mp_read_map(buf, pos, code & 0x0F, depth + 1)
    if 0x90 <= code <= 0x9F:
        return _mp_read_array(buf, pos, code & 0x0F, depth + 1)
    if 0xA0 <= code <= 0xBF:
        return _mp_read_str(buf, pos, code & 0x1F)
    if code == 0xC0:
        return None, pos
    if code == 0xC2:
        return False, pos
    if code == 0xC3:
        return True, pos
    if code in (0xC4, 0xC5, 0xC6):
        width = 1 << (code - 0xC4)
        size = int.from_bytes(buf[pos:pos + width], 'big')
        pos += width
        return bytes(buf[pos:pos + size]), pos + size
    if code in (0xC7, 0xC8, 0xC9):
        width = 1 << (code - 0xC7)
        size = int.from_bytes(buf[pos:pos + width], 'big')
        return _mp_read_ext(buf, pos + width, size)
    if code == 0xCA:
        return struct.unpack_from('>f', buf, pos)[0], pos + 4
    if code == 0xCB:
        return struct.unpack_from('>d', buf, pos)[0], pos + 8
    if 0xCC <= code <= 0xCF:
        width = 1 << (code - 0xCC)
        return int.from_bytes(buf[pos:pos + width], 'big'), pos + width
    if 0xD0 <= code <= 0xD3:
        width = 1 << (code - 0xD0)
        return int.from_bytes(buf[pos:pos + width], 'big', signed=True), pos + width
    if 0xD4 <= code <= 0xD8:
        return _mp_read_ext(buf, pos, 1 << (code - 0xD4))
    if code in (0xD9, 0xDA, 0xDB):
        width = 1 << (code - 0xD9)
        size = int.from_bytes(buf[pos:pos + width], 'big')
        pos += width
        return _mp_read_str(buf, pos, size)
    if code in (0xDC, 0xDD):
        width = 2 if code == 0xDC else 4
        size = int.from_bytes(buf[pos:pos + width], 'big')
        return _mp_read_array(buf, pos + width, size, depth + 1)
    if code in (0xDE, 0xDF):
        width = 2 if code == 0xDE else 4
        size = int.from_bytes(buf[pos:pos + width], 'big')
        return _mp_read_map(buf, pos + width, size, depth + 1)
    raise ValueError('unsupported msgpack code 0x%02X' % code)


def _mp_unpack_all(blob):
    """Every top-level value in the stream; VS appends one per message."""
    out, pos, size = [], 0, len(blob)
    while pos < size:
        value, pos = _mp_read(blob, pos)
        out.append(value)
    return out


def _vs_installed():
    """Whether Visual Studio is installed, from the installer's own instance registry.

    Independent of install location, which a Program Files check is not."""
    instances = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / \
        'Microsoft' / 'VisualStudio' / 'Packages' / '_Instances'
    try:
        return any(instances.iterdir())
    except OSError:
        return False


def _vs_solution_roots():
    """The scanned user's own tree only. ~/source/repos is absent because it sits under
    ~/source. Shared roots like C:\\src are walked by every user and nothing in one says
    whose a session is; those conversations still arrive through the chat log."""
    home = Path.home()
    roots = []
    for root in (home / 'source', home / 'Documents'):
        try:
            if root.is_dir():
                roots.append(root)
        except OSError:
            continue
    return roots


def _vs_within(root, path):
    """Whether path is still under root once junctions and symlinks are resolved."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        return resolved == root or root in resolved.parents
    except OSError:
        return False


def _vs_file_key(info):
    return (info.st_dev, info.st_ino)


def _vs_is_link(info):
    """Whether a no-follow stat landed on a symlink or an NTFS reparse point."""
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, 'st_file_attributes', 0) & _VS_REPARSE_POINT)


def _vs_plain_stat(path):
    """A regular file's own identity, or None.

    Narrows the race rather than ending it. A no-follow stat keeps the final component
    from supplying an identity that is not its own, and a link count above one rejects a
    file reachable from outside the tree. Neither covers a directory above it: every
    level of the session path belongs to the user, so a junction there still resolves the
    walk and the read to different files. Only running as that user closes it."""
    try:
        info = os.lstat(str(path))
    except OSError:
        return None
    if _vs_is_link(info):
        log_error('visual studio path is a link: %s' % path, 'visual_studio')
        return None
    if getattr(info, 'st_nlink', 1) > 1:
        log_error('visual studio path is hard-linked: %s' % path, 'visual_studio')
        return None
    return info if stat.S_ISREG(info.st_mode) else None


def _vs_open_verified(path, root, key):
    """The file the walk cleared, or None. Checking the path again still races a junction
    planted in between, so the open handle is checked instead."""
    if not _vs_within(root, path):
        log_error('visual studio path escapes its root: %s' % path, 'visual_studio')
        return None
    try:
        handle = open(path, 'rb')
    except OSError as e:
        log_error('visual studio file unreadable (%s): %s' % (path, e), 'visual_studio')
        return None
    try:
        opened = os.fstat(handle.fileno())
        if getattr(opened, 'st_nlink', 1) > 1 or _vs_file_key(opened) != key:
            log_error('visual studio file changed under the walk: %s' % path, 'visual_studio')
            handle.close()
            return None
    except OSError:
        handle.close()
        return None
    return handle


def _iter_vs_sessions(cutoff_mtime, budget=None):
    """Session files newer than the cutoff, from solutions at most two levels under a root.

    `budget` is a one-element list set to True when the walk stops early."""
    seen = set()
    scanned = 0
    found = []
    for root in _vs_solution_roots():
        try:
            real_root = Path(os.path.realpath(str(root)))
        except OSError:
            continue
        for depth in ('', '*/', '*/*/'):
            # glob() only builds a generator; the disk is touched by iterating it.
            try:
                for path in root.glob(depth + _VS_SESSION_TAIL):
                    scanned += 1
                    if scanned > _VS_MAX_WALK_DIRS:
                        log_error('visual studio walk hit its directory budget', 'visual_studio')
                        if budget is not None:
                            budget[0] = True
                        return sorted(found, key=lambda item: (item[0], str(item[1])))
                    key = str(path)
                    if key in seen:
                        continue
                    seen.add(key)
                    info = _vs_plain_stat(path)
                    if info is None or info.st_size > _VS_MAX_SESSION_BYTES:
                        continue
                    if info.st_mtime < cutoff_mtime:
                        continue
                    # A junction out of the tree would be read with the sweep's own rights.
                    if not _vs_within(real_root, path):
                        log_error('visual studio session escapes its root: %s' % path,
                                  'visual_studio')
                        continue
                    found.append((info.st_mtime, path, real_root, _vs_file_key(info)))
            except OSError as e:
                log_error('visual studio walk failed under %s: %s' % (root, e), 'visual_studio')
                continue
    # Oldest first, so a run stopped by the cap can resume past what it finished.
    return sorted(found, key=lambda item: (item[0], str(item[1])))


def _vs_block_text(payload):
    """Concatenated text blocks of one message; tool-call blocks carry no prose and are skipped."""
    parts = []
    for block in payload.get('Content') or []:
        if not (isinstance(block, list) and len(block) > 1 and isinstance(block[1], dict)):
            continue
        if block[0] != _VS_TEXT_BLOCK:
            continue
        text = block[1].get('Content')
        if isinstance(text, str) and text.strip():
            parts.append(text)
    return '\n\n'.join(parts)


def _vs_model_name(payload):
    """Model recorded on a message; VS writes it as a map, or a list whose second item holds it."""
    model = payload.get('Model')
    if isinstance(model, list):
        model = next((item for item in model if isinstance(item, dict)), None)
    if isinstance(model, dict):
        name = model.get('Family') or model.get('ModelId')
        if isinstance(name, str) and name:
            return name
    return None


def _vs_iso(epoch):
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace('+00:00', 'Z')
    except (OverflowError, OSError, ValueError):
        return None


def _vs_timestamp(payload):
    """Wall-clock for a message. Only replies carry one, on the quota snapshot taken with them."""
    for key in ('Timestamp', 'TimeCreated'):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return _vs_iso(value)
    for quota in payload.get('Quotas') or []:
        if isinstance(quota, dict) and isinstance(quota.get('Timestamp'), (int, float)):
            return _vs_iso(quota['Timestamp'])
    return None


def _vs_session_id(value):
    """Session ids are compared across two sources, and the log's regex accepts either case."""
    return value.lower() if isinstance(value, str) else value


def _vs_session_turns(objects):
    """Settled (prompt, reply) pairs; VS tags 0 as the prompt and 1 as the reply.

    A reply with no text yet is still running. Waiting is safe rather than lossy: VS
    rewrites the entry once the turn completes, so it arrives on a later sweep."""
    turns, pending, index = [], None, -1
    for obj in objects:
        if not (isinstance(obj, list) and len(obj) == 2 and isinstance(obj[1], dict)):
            continue
        role, payload = obj[0], obj[1]
        if role == _VS_ROLE_USER:
            pending = payload
            index += 1
        elif role == _VS_ROLE_ASSISTANT and pending is not None:
            turns.append((index, pending, payload))
            pending = None
    return [(i, p, r) for i, p, r in turns if _vs_block_text(r).strip()]


def _vs_capped_lines(handle):
    """Lines bounded in count and in length. KEEP IN SYNC: mdm/setup.py's
    _backfill_capped_lines. A count cap alone does not bound memory."""
    count = 0
    while count < _VS_MAX_LOG_LINES:
        line = handle.readline(_VS_MAX_LOG_LINE_CHARS)
        if not line:
            return
        count += 1
        if len(line) >= _VS_MAX_LOG_LINE_CHARS and not line.endswith('\n'):
            while count < _VS_MAX_LOG_LINES:
                rest = handle.readline(_VS_MAX_LOG_LINE_CHARS)
                count += 1
                if not rest or rest.endswith('\n'):
                    break
            continue
        yield line


def _iter_vs_chat_logs(cutoff_mtime):
    """Visual Studio's live per-request chat log, newest first. Derived from the scanned
    home rather than %LOCALAPPDATA%, which points at the caller when a sweep runs per-user."""
    root = Path.home() / 'AppData' / 'Local' / 'Temp' / 'VSGitHubCopilotLogs'
    found = []
    try:
        real_root = Path(os.path.realpath(str(root)))
        for path in root.glob('*_VSGitHubCopilot.chat.log'):
            info = _vs_plain_stat(path)
            if info is None or info.st_mtime < cutoff_mtime:
                continue
            # A junction out of the tree would be read with the sweep's own rights.
            if not _vs_within(real_root, path):
                log_error('visual studio chat log escapes its root: %s' % path, 'visual_studio')
                continue
            found.append((info.st_mtime, path, _vs_file_key(info)))
    except OSError:
        return []
    # Oldest first: a restart replays the whole history, and the first write of a turn wins.
    return [(real_root, path, key) for _, path, key in sorted(found, key=lambda i: i[0])]


def _vs_log_line_time(line):
    """`[2026-09-21 13:33:05.862 Conversations V]` -> ISO UTC. The stamp is machine-local."""
    match = _VS_LOG_TIME_RE.match(line)
    if not match:
        return None
    try:
        naive = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
        return naive.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except (OverflowError, OSError, ValueError):
        return None


def _vs_usage_from_line(line):
    """`[CopilotClient EventType(11)] [{"InputTokenCount":5187,...}]` -> usage dict.

    2022 leaves CachedInputTokenCount null and puts the figure under AdditionalCounts.
    Cached tokens come out of input, which the other surfaces bill separately."""
    start = line.find('[{')
    if start < 0:
        return None
    try:
        entries = json.loads(line[start:])
    except ValueError:
        return None
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return None
    entry = entries[0]
    total_in = entry.get('InputTokenCount')
    out = entry.get('OutputTokenCount')
    if not isinstance(total_in, int) or not isinstance(out, int):
        return None
    cached = entry.get('CachedInputTokenCount')
    if not isinstance(cached, int):
        extra = entry.get('AdditionalCounts')
        cached = (extra or {}).get('prompt_tokens_details_cached_tokens')
    cached = cached if isinstance(cached, int) else 0
    return {'input_tokens': max(total_in - cached, 0),
            'output_tokens': out,
            'cache_read_input_tokens': cached}


def _vs_add_usage(into, extra):
    """Agent mode bills several calls per user turn, so a turn's usage is their sum."""
    for field in ('input_tokens', 'output_tokens', 'cache_read_input_tokens'):
        into[field] = into.get(field, 0) + extra.get(field, 0)


def _vs_user_messages(body):
    """The prompts a person actually typed. VS 2026 prepends a synthetic `user` message
    carrying editor state; counting it puts every later turn's usage on its neighbour."""
    out = []
    for message in body.get('messages') or []:
        if not isinstance(message, dict) or message.get('role') != 'user':
            continue
        content = message.get('content')
        if isinstance(content, str) and not content.startswith(_VS_SYNTHETIC_USER_PREFIX):
            out.append(content)
    return out


def _vs_seek_tail(handle, path):
    """Start a long log at its tail, and say whether it did. Reading the head would spend
    the line budget on ancient requests and never reach what the sweep is here for."""
    try:
        size = os.fstat(handle.fileno()).st_size
        if size <= _VS_MAX_LOG_BYTES:
            return False
        handle.seek(size - _VS_MAX_LOG_BYTES)
        handle.readline()
    except OSError:
        return False
    log_error('visual studio chat log read from its tail: %s' % path.name, 'visual_studio')
    return True


def _vs_chat_log_requests(path, root, key):
    """Requests oldest-first as (timestamp, model, turn_index, body, session_id), plus
    usage keyed by (session_id, turn_index).

    Read forward: the `SessionId=` marker preceding a request is the only thing tying it
    to a chat, and the log filename names the VS process, so it would merge unrelated
    chats. Turns are keyed by position, never text -- agent mode issues several requests
    per turn, and keying on the prompt would merge two that both say "continue"."""
    requests, usage_by_turn = [], {}
    slot = None
    session_id = None
    raw = _vs_open_verified(path, root, key)
    if raw is None:
        return [], {}
    seeked = _vs_seek_tail(raw, path)
    try:
        with io.TextIOWrapper(raw, encoding='utf-8', errors='replace') as handle:
            for line in _vs_capped_lines(handle):
                marker = _VS_SESSION_RE.search(line)
                if marker:
                    session_id = _vs_session_id(marker.group(1))
                    seeked = False
                    continue
                # Started mid-file, so nothing here is tied to a chat until a marker is.
                if seeked:
                    continue
                if _VS_USAGE_MARKER in line:
                    # Usage is logged after the request it belongs to.
                    usage = _vs_usage_from_line(line)
                    if usage and slot is not None:
                        _vs_add_usage(usage_by_turn.setdefault(slot, {}), usage)
                    continue
                if '"messages"' not in line:
                    continue
                start = line.find('{"')
                if start < 0:
                    continue
                try:
                    body = json.loads(line[start:])
                except ValueError:
                    continue
                if not isinstance(body, dict) or not body.get('messages'):
                    continue
                turn_index = max(len(_vs_user_messages(body)) - 1, 0)
                slot = (session_id, turn_index)
                requests.append((_vs_log_line_time(line), body.get('model'),
                                 turn_index, body, session_id))
    except OSError:
        return [], {}
    return _vs_recent_per_session(requests), usage_by_turn


def _vs_recent_per_session(requests):
    """The most recent requests of each conversation. A single tail would drop a whole
    chat that a busier one in the same log outran."""
    counts, kept = {}, []
    for item in reversed(requests):
        session_id = item[4]
        if counts.get(session_id, 0) >= _VS_MAX_METADATA_REQUESTS:
            continue
        counts[session_id] = counts.get(session_id, 0) + 1
        kept.append(item)
        if len(kept) >= _VS_MAX_KEPT_REQUESTS:
            log_error('visual studio log held more requests than one run reads',
                      'visual_studio')
            break
    kept.reverse()
    return kept


def _vs_chat_log_turns(body):
    """Settled (prompt, reply) pairs from one request body.

    VS never logs a response; it replays it as history on the next call, so the trailing
    turn is withheld until a later prompt settles it. Only the trailing one: filtering by
    text would also remove an earlier turn that repeated the same prompt."""
    turns, prompt, reply, index = [], None, [], 0
    for message in body.get('messages') or []:
        if not isinstance(message, dict):
            continue
        role, content = message.get('role'), message.get('content')
        if not isinstance(content, str):
            continue
        if role == 'user':
            if content.startswith(_VS_SYNTHETIC_USER_PREFIX):
                continue
            if prompt is not None:
                turns.append((index, prompt, '\n\n'.join(reply)))
                index += 1
            prompt, reply = content, []
        elif role == 'assistant' and prompt is not None and content.strip():
            reply.append(content)
    return [(i, p, r) for i, p, r in turns if p.strip() and r.strip()]


def _vs_session(sessions, session_id):
    return sessions.setdefault(
        session_id, {'session_id': session_id, 'agent_surface': 'visual_studio', 'turns': {}})


def _vs_turn_marker(conversation_id, prompt, index):
    """Stable id, derived identically from either source. Scoped to its conversation, or
    two chats opening with "continue" collide. Excludes the reply, which grows across
    agent-mode calls while the turn still runs and would record it twice."""
    digest = hashlib.sha256()
    digest.update((conversation_id or '').encode('utf-8', 'replace'))
    digest.update(b'\x00')
    digest.update((prompt or '').encode('utf-8', 'replace'))
    digest.update(b'\x00%d' % index)
    return 'vs-' + digest.hexdigest()[:24]


def _vs_add_turn(session, index, prompt, reply, model, timestamp, usage):
    """Record one turn at its own position; the first source to reach it wins."""
    session['turns'].setdefault(index, (prompt, reply, model, timestamp, usage))


def _vs_finalize(session):
    """The two entries parse_copilot_session walks, plus one usage slot per exchange.
    Positions can skip a cancelled turn but the backend pairs usage[i] with exchange i,
    so the slots are packed here while the position keeps feeding the id."""
    turns = session.pop('turns')
    entries, usage = [], []
    for index in sorted(turns):
        prompt, reply, model, timestamp, turn_usage = turns[index]
        entry = {'type': 'user.message',
                 'id': _vs_turn_marker(session['session_id'], prompt, index),
                 'data': {'content': prompt}}
        if timestamp:
            entry['timestamp'] = timestamp
        entries.append(entry)
        entries.append({'type': 'assistant.message',
                        'data': {'content': reply, 'model': model or 'auto'}})
        usage.append(turn_usage or {})
    return entries, usage


def _vs_collect_chat_logs(cutoff, sessions, logged):
    """Live source: prompts land here per request, and it is the only one carrying usage."""
    for root, path, key in _iter_vs_chat_logs(cutoff):
        fallback_id = path.stem.replace('_VSGitHubCopilot.chat', '')
        requests, usage_by_turn = _vs_chat_log_requests(path, root, key)
        # A turn belongs to the request it was the intent of, not to one replaying it.
        for timestamp, model, turn_index, _, session_id in requests:
            key = (_vs_session_id(session_id or fallback_id), turn_index)
            if key not in logged:
                logged[key] = (timestamp, model,
                               usage_by_turn.get((session_id, turn_index)))
        for timestamp, model, _, body, session_id in requests:
            conversation_id = _vs_session_id(session_id or fallback_id)
            if not session_id:
                log_error('visual studio request had no session marker in %s' % path.name,
                          'visual_studio')
            session = _vs_session(sessions, conversation_id)
            for index, prompt, reply in _vs_chat_log_turns(body):
                key = (conversation_id, index)
                usage = usage_by_turn.get((session_id, index))
                own_time, own_model, _ = logged.get(key, (None, None, None))
                logged[key] = (own_time or timestamp, own_model or model, usage)
                _vs_add_turn(session, index, prompt, reply,
                             own_model or model, own_time or timestamp, usage)


def _vs_collect_stores(cutoff, sessions, truncated, logged, resume):
    """Backstop for turns the chat log withheld or lost. Usage comes from the log."""
    undiscovered = [False]
    for count, (mtime, path, root, key) in enumerate(_iter_vs_sessions(cutoff, undiscovered)):
        if count >= _VS_MAX_SESSIONS_PER_RUN:
            log_error('visual studio session cap reached; remaining files deferred',
                      'visual_studio')
            truncated[0] = True
            break
        handle = _vs_open_verified(path, root, key)
        if handle is None:
            continue
        try:
            with handle:
                objects = _mp_unpack_all(handle.read())
        except (OSError, ValueError, IndexError, struct.error) as e:
            log_error('visual studio session unreadable (%s): %s' % (path.name, e), 'visual_studio')
            continue
        session = _vs_session(sessions, _vs_session_id(path.name))
        for index, prompt_payload, reply_payload in _vs_session_turns(objects):
            prompt = _vs_block_text(prompt_payload)
            if not prompt:
                continue
            # The log holds real token counts even when only the store holds the reply.
            own_time, own_model, usage = logged.get(
                (_vs_session_id(path.name), index), (None, None, None))
            _vs_add_turn(session, index, prompt, _vs_block_text(reply_payload),
                         own_model or _vs_model_name(reply_payload)
                         or _vs_model_name(prompt_payload),
                         own_time or _vs_timestamp(reply_payload)
                         or _vs_timestamp(prompt_payload),
                         usage)
        resume[0] = mtime
    if undiscovered[0]:
        # The walk stopped mid-glob, so what it never reached may be older than the last
        # file it read. Only a complete walk sorts by mtime, and only that can resume.
        truncated[0] = True
        resume[0] = None


def collect_visual_studio_sessions(cutoff):
    """Visual Studio Copilot conversations touched since the cutoff, in backfill shape.

    Returns (sessions, truncated, resume_at). A truncated walk left files unread; the
    caller advances its cutoff only as far as resume_at, or not at all if that is None."""
    if not _is_windows() or not _vs_installed():
        return [], False, None
    sessions, truncated, logged, resume = {}, [False], {}, [None]
    # Chat logs first: a superset of the .vs stores and the only source with real usage.
    _vs_collect_chat_logs(cutoff, sessions, logged)
    _vs_collect_stores(cutoff, sessions, truncated, logged, resume)
    out = []
    for session in sessions.values():
        entries, usage = _vs_finalize(session)
        if not entries:
            continue
        session['entries'] = entries
        # A list of empty slots says nothing the backend cannot work out itself.
        if any(usage):
            session['usage'] = usage
        out.append(session)
    # Everything older than the last finished store file has been read, chat logs included.
    return out, truncated[0], (resume[0] if truncated[0] else None)


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/copilot"
    data = json.dumps(exchange).encode()

    for attempt in range(3):
        try:
            result = subprocess.run(
                _curl_base() + ["-fsSL", "-X", "POST",
                 "-H", f"Authorization: Bearer {api_key}",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data,
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                return True
            error_msg = result.stderr.decode('utf-8', errors='ignore').strip() if result.stderr else "Unknown error"
            log_error(f"API request failed: {error_msg}", 'api_call', {'payload_size_bytes': len(data)})
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
            os.chmod(temporary_path, 0o700)
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
                api_key = _machine_env('UNBOUND_COPILOT_API_KEY')
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


def _mcp_scan_command(installer_path, server_name, backend_url):
    if _is_windows():
        return [
            _windows_system32_path("WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(installer_path),
            "-McpScan", "-McpServerName", server_name, "-Domain", backend_url,
        ]
    return ["bash", str(installer_path), "mcp-scan", "--name", server_name,
            "--domain", backend_url]


def _dispatch_mcp_server_scan(server_name, server_config, cwd=None):
    if not server_name or not isinstance(server_config, dict):
        return
    try:
        if server_config.get('command') and not server_config.get('script_content'):
            # Hash and body from one snapshot: the backend re-hashes the body, so
            # a file edited since the policy call must not split the two apart.
            snapshot = _hook_script_snapshot(
                server_config.get('command'), server_config.get('args'), cwd)
            if snapshot:
                server_config = {**server_config, 'scriptHash': snapshot[0],
                                 'script_content': snapshot[1]}
    except Exception as exc:
        log_error("mcp scan dispatch: no script body for %s: %s"
                  % (server_name, type(exc).__name__), 'mcp_server')
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
            api_key = _machine_env('UNBOUND_COPILOT_API_KEY')
            backend_url = _machine_env('UNBOUND_BACKEND_URL')
            if backend_url and not backend_url.startswith("https://"):
                log_error("mcp scan dispatch: env base_url is not https, ignoring", 'mcp_server')
                backend_url = None
        if not api_key or not backend_url:
            return

        if RUNNING_FROZEN:
            if not os.path.isfile(FROZEN_DISCOVERY_BIN):
                return
            scan_cmd = [FROZEN_DISCOVERY_BIN, "mcp-scan", "--name", server_name,
                        "--domain", backend_url]
        else:
            installer_path, installer_url = _discovery_installer()
            if not _ensure_discovery_installer(installer_path, installer_url):
                return
            scan_cmd = _mcp_scan_command(installer_path, server_name, backend_url)

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


# ---------------------------------------------------------------------------
# Unresolved-MCP diagnostic: when a VS Code `mcp_<server>_<tool>` call matches no
# configured server, a detached child inventories every MCP config on disk (the
# ones this hook reads AND the ones it doesn't) and uploads a text report to
# /v1/hooks/mcp-diagnostics, which stores it and pings Slack on first sight.
# ---------------------------------------------------------------------------

def _mcp_diag_server_hint(raw_tool):
    """Server token of `mcp_<server>_<tool>` up to the first '_' (VS Code keeps '-')."""
    body = raw_tool[len('mcp_'):] if raw_tool.lower().startswith('mcp_') else raw_tool
    return (body.split('_', 1)[0] or raw_tool)[:255]


_MCP_DIAG_SECRETISH = re.compile(
    r'(?i)(authorization|bearer|api[_-]?key|apikey|token|secret|password|passwd|credential)')


def _mcp_diag_host_of(url):
    # scheme://hostname[:port] only: URL paths, queries and userinfo can carry credentials.
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.hostname:
            return '%s://%s%s' % (parsed.scheme, parsed.hostname, ':%d' % parsed.port if parsed.port else '')
    except Exception:
        pass
    return '<unparseable-url>'


def _mcp_diag_summarize(entry):
    """Compact, secret-free summary of one server config: no args, env or headers."""
    if not isinstance(entry, dict):
        return '<no config>'
    bits = []
    if entry.get('type'):
        bits.append(str(entry['type'])[:20])
    url = entry.get('url') or entry.get('serverUrl')
    if isinstance(url, str) and url:
        bits.append(_mcp_diag_host_of(url))
    command = entry.get('command')
    if isinstance(command, str) and command:
        bits.append('cmd=%s' % os.path.basename(command)[:60])
    if isinstance(entry.get('args'), list) and entry['args']:
        bits.append('args=%d' % len(entry['args']))
    return ', '.join(bits) or '<empty>'


def _mcp_diag_read_json(path):
    """(status, parsed) for one JSON/JSONC file; never raises."""
    try:
        if not path.is_file():
            return 'missing', None
        if path.stat().st_size > MCP_DIAG_MAX_CONFIG_BYTES:
            return 'too large', None
        return 'ok', _parse_jsonc(path.read_text(encoding='utf-8'))
    except Exception as exc:
        return 'unreadable (%s)' % type(exc).__name__, None


def _mcp_diag_config_servers(path, allow_bare=False):
    status, config = _mcp_diag_read_json(path)
    if status != 'ok':
        return status, {}
    raw = _mcp_servers_from_config(config, allow_bare=allow_bare) if isinstance(config, dict) else None
    if not raw:
        return 'no servers', {}
    return 'ok', {str(name): _mcp_diag_summarize(entry) for name, entry in raw.items()}


def _mcp_diag_hook_sources(cwd):
    """Every source read_copilot_mcp_servers consults, file by file."""
    rows = []
    plugin_list = _plugin_mcp_config_paths()
    plugin_paths = set(plugin_list)
    workspace_paths = set(_workspace_mcp_config_paths(cwd))
    for path in _copilot_mcp_config_paths(cwd, plugin_list):
        allow_bare = path.name == '.mcp.json' or (
            path.name == 'mcp.json' and path.parent.name == '.github'
        )
        kind = 'plugin' if path in plugin_paths else (
            'workspace' if path in workspace_paths else 'user'
        )
        status, servers = _mcp_diag_config_servers(path, allow_bare)
        rows.append({'source': kind, 'file': str(path), 'status': status, 'servers': servers})
    try:
        providers = _copilot_provider_servers_from_cache(_read_mcp_tools_cache())
        rows.append({'source': 'validated-provider', 'file': 'mcp-tools-cache.json', 'status': 'ok',
                     'servers': {n: _mcp_diag_summarize(c) for n, c in providers.items()}})
    except Exception as exc:
        rows.append({'source': 'validated-provider', 'file': 'mcp-tools-cache.json',
                     'status': 'failed (%s)' % type(exc).__name__, 'servers': {}})
    try:
        cached = {n: _mcp_diag_summarize(f) for n, f in _vscode_cached_mcp_servers(cwd)}
        rows.append({'source': 'provider', 'file': 'VS Code state.vscdb', 'status': 'ok', 'servers': cached})
    except Exception as exc:
        rows.append({'source': 'provider', 'file': 'VS Code state.vscdb',
                     'status': 'failed (%s)' % type(exc).__name__, 'servers': {}})
    return rows


def _mcp_diag_claude_plugin_dirs(claude_dir):
    dirs = {}
    root = claude_dir / 'plugins'
    _status, installed = _mcp_diag_read_json(root / 'installed_plugins.json')
    if isinstance(installed, dict):
        for full_name, entries in (installed.get('plugins') or {}).items():
            for entry in (entries or []):
                if isinstance(entry, dict) and entry.get('installPath'):
                    dirs[Path(entry['installPath'])] = full_name
    if dirs:
        # The cache also keeps every superseded version; only the installed one is live.
        return dirs
    try:
        for marketplace in (m for m in (root / 'cache').iterdir() if m.is_dir()):
            for plugin in (p for p in marketplace.iterdir() if p.is_dir()):
                for version in (v for v in plugin.iterdir() if v.is_dir()):
                    dirs.setdefault(version, '%s@%s' % (plugin.name, marketplace.name))
    except OSError:
        pass
    return dirs


def _mcp_diag_unread_sources(cwd):
    """MCP configs this hook never reads but VS Code may still load: other apps'
    configs (VS Code can import them), Claude Code config + plugins, and
    `.vscode/mcp.json` above the cwd."""
    home = Path.home()
    system = platform.system()
    if system == 'Windows':
        app_support = Path(os.environ.get('APPDATA') or home)
    elif system == 'Darwin':
        app_support = home / 'Library' / 'Application Support'
    else:
        app_support = home / '.config'
    rows = []

    def add(source, path, allow_bare=False):
        status, servers = _mcp_diag_config_servers(path, allow_bare)
        if status not in ('missing', 'no servers'):
            rows.append({'source': source, 'file': str(path), 'status': status, 'servers': servers})

    add('Claude Desktop', app_support / 'Claude' / 'claude_desktop_config.json')
    add('Cursor', home / '.cursor' / 'mcp.json')
    add('Windsurf', home / '.codeium' / 'windsurf' / 'mcp_config.json')
    for editor in ('VSCodium', 'Code - OSS'):
        add('%s user' % editor, app_support / editor / 'User' / 'mcp.json')

    claude_dir = Path(os.environ.get('CLAUDE_CONFIG_DIR') or home / '.claude')
    claude_json = home / '.claude.json'
    status, data = _mcp_diag_read_json(claude_json)
    if isinstance(data, dict):
        top = data.get('mcpServers')
        if isinstance(top, dict) and top:
            rows.append({'source': 'Claude Code user', 'file': str(claude_json), 'status': 'ok',
                         'servers': {n: _mcp_diag_summarize(e) for n, e in top.items()}})
        for project, entry in (data.get('projects') or {}).items():
            servers = entry.get('mcpServers') if isinstance(entry, dict) else None
            if isinstance(servers, dict) and servers:
                rows.append({'source': 'Claude Code project %s' % project, 'file': str(claude_json),
                             'status': 'ok',
                             'servers': {n: _mcp_diag_summarize(e) for n, e in servers.items()}})
    elif status != 'missing':
        rows.append({'source': 'Claude Code user', 'file': str(claude_json), 'status': status, 'servers': {}})

    for plugin_dir, plugin_name in _mcp_diag_claude_plugin_dirs(claude_dir).items():
        add('Claude Code plugin %s' % plugin_name, plugin_dir / '.mcp.json', allow_bare=True)
        add('Claude Code plugin %s' % plugin_name, plugin_dir / '.claude-plugin' / 'plugin.json')

    if cwd:
        try:
            start = Path(cwd).resolve()
            for directory in start.parents:
                add('.vscode above cwd', directory / '.vscode' / 'mcp.json')
            for directory in [start] + list(start.parents):
                add('Cursor workspace', directory / '.cursor' / 'mcp.json')
        except OSError:
            pass
    return rows


def _mcp_diag_matches(raw_tool, groups):
    """Server names whose VS Code tool prefix (full or 13-char truncated) produces
    raw_tool, and looser near-misses on the parsed server token."""
    # Match against the name with and without the mcp_ prefix: VS Code strips it to
    # build the tool name, but a server can also be called `mcp_<something>` itself.
    bodies = (_vscode_sanitize(raw_tool[len('mcp_'):]), _vscode_sanitize(raw_tool))
    hint = _vscode_sanitize(_mcp_diag_server_hint(raw_tool))
    exact, near = [], []
    for group in groups:
        for name, summary in (group.get('servers') or {}).items():
            aliases = _vscode_server_aliases(name)
            prefixes = aliases | {a[:_VSCODE_TRUNCATED_SERVER_LENGTH] for a in aliases}
            row = {'name': name, 'source': group['source'], 'file': group['file'], 'cfg': summary}
            if any(body.startswith(p + '_') for p in prefixes for body in bodies):
                exact.append(row)
            elif len(hint) >= 3 and any(hint in a or (len(a) >= 3 and a in hint) for a in aliases):
                near.append(row)
    return {'exact': exact, 'near': near}


def _mcp_diag_vscode_server_logs(hint):
    """VS Code's own record of the servers it started: one
    `mcpServer.<collection>.<server>.log` per server per window, where the
    collection says where the definition came from (e.g. mcp.config.usrlocal =
    user mcp.json). Newest two log sessions per VS Code flavour; names only."""
    rows = []
    for user_dir in _vscode_user_dirs():
        logs_root = user_dir.parent / 'logs'
        try:
            sessions = sorted((d for d in logs_root.iterdir() if d.is_dir()), key=lambda d: d.name)[-2:]
        except OSError:
            continue
        for session in sessions:
            try:
                files = sorted(session.glob('window*/mcpServer.*.log'))
            except OSError:
                continue
            for log_file in files:
                name = log_file.name[len('mcpServer.'):-len('.log')]
                mark = hint and hint in _vscode_sanitize(name)
                rows.append('%s/%s/%s%s' % (
                    user_dir.parent.name, session.name, name, '   <-- matches tool' if mark else ''))
    return rows[-60:]


def _mcp_diag_extension_providers():
    """Installed VS Code extensions that contribute MCP servers (no config file:
    VS Code asks the extension at runtime), plus the Copilot Chat version."""
    rows = []
    for ext_root in (Path.home() / '.vscode' / 'extensions',
                     Path.home() / '.vscode-insiders' / 'extensions'):
        try:
            ext_dirs = sorted(d for d in ext_root.iterdir() if d.is_dir())
        except OSError:
            continue
        for ext_dir in ext_dirs:
            if ext_dir.name.startswith('github.copilot-chat-'):
                rows.append('%s (Copilot Chat)' % ext_dir.name)
            _status, manifest = _mcp_diag_read_json(ext_dir / 'package.json')
            contributes = manifest.get('contributes') if isinstance(manifest, dict) else None
            providers = contributes.get('mcpServerDefinitionProviders') if isinstance(contributes, dict) else None
            if not isinstance(providers, list):
                continue
            labels = ', '.join(
                '%s (%s)' % (p.get('label'), p.get('id')) for p in providers if isinstance(p, dict))
            rows.append('%s: %s' % (ext_dir.name, labels))
    return rows


def _mcp_diag_path_binary(name):
    """The child inherits the editor's workspace as its cwd, and Windows searches
    that directory before PATH, so a repo could ship its own copilot.exe. Resolve
    from absolute PATH entries only — a relative entry like `bin` resolves inside
    the workspace too — and refuse anything that still lands under the cwd."""
    entries = [e for e in (os.environ.get('PATH') or '').split(os.pathsep) if os.path.isabs(e)]
    found = shutil.which(name, path=os.pathsep.join(entries))
    if not found:
        return None
    try:
        resolved = str(Path(found).resolve())
        cwd = str(Path.cwd().resolve())
    except (OSError, ValueError):
        return None
    if resolved == cwd or resolved.startswith(cwd + os.sep):
        return None
    return resolved


def _mcp_diag_copilot_cli_list():
    """`copilot mcp list --json`: the Copilot CLI's own resolved view (user,
    workspace, plugin, builtin), summarized without args/env/headers."""
    binary = _mcp_diag_path_binary('copilot')
    if not binary:
        return {'status': 'copilot CLI not resolved from PATH', 'servers': {}}
    try:
        proc = subprocess.run([binary, 'mcp', 'list', '--json'], capture_output=True,
                              text=True, timeout=30, stdin=subprocess.DEVNULL)
        data = json.loads(proc.stdout or '{}')
    except Exception as exc:
        return {'status': 'failed (%s)' % type(exc).__name__, 'servers': {}}
    servers = data.get('mcpServers') if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return {'status': 'unexpected output (exit %s)' % proc.returncode, 'servers': {}}
    return {'status': 'ok', 'servers': {
        name: '%s, source=%s%s' % (_mcp_diag_summarize(entry), entry.get('source'),
                                  '' if entry.get('enabled', True) else ', DISABLED')
        for name, entry in servers.items() if isinstance(entry, dict)
    }}


def _mcp_diag_scrub_value(value):
    """Drop a credential-bearing value whole, the boundary the Claude Code
    diagnostic applies to the free text it collects."""
    text = str(value)
    if _MCP_DIAG_SECRETISH.search(text):
        return '<redacted>'
    return text[:200]


def _mcp_diag_vscode_settings():
    """chat.mcp.* settings (e.g. discovery of other apps' servers) per VS Code user dir."""
    out = {}
    for user_dir in _vscode_user_dirs():
        _status, settings = _mcp_diag_read_json(user_dir / 'settings.json')
        if not isinstance(settings, dict):
            continue
        for key, value in settings.items():
            if not key.startswith('chat.mcp'):
                continue
            if isinstance(value, (bool, int, str)):
                out['%s: %s' % (user_dir.parent.name, key)] = _mcp_diag_scrub_value(value)
            elif isinstance(value, dict):
                out['%s: %s' % (user_dir.parent.name, key)] = _mcp_diag_scrub_value(json.dumps(value))
    return out


def _mcp_diag_error_log_tail():
    try:
        lines = ERROR_LOG.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return []
    kept, dropped = [], 0
    for line in lines:
        if 'mcp' not in line.lower():
            continue
        if _MCP_DIAG_SECRETISH.search(line):
            dropped += 1
            continue
        kept.append(line[:300])
    kept = kept[-15:]
    if dropped:
        kept.append('[%d credential-bearing line(s) suppressed]' % dropped)
    return kept


def _build_mcp_diagnostic(raw_tool, cwd):
    servers, server_sources, ambiguous = _read_copilot_mcp_servers_with_sources(cwd)
    resolved = resolve_copilot_mcp(raw_tool, servers)
    hook_sources = _mcp_diag_hook_sources(cwd)
    unread_sources = _mcp_diag_unread_sources(cwd)
    copilot_cli = _mcp_diag_copilot_cli_list()
    cli_group = {'source': 'copilot mcp list', 'file': 'copilot CLI', 'servers': copilot_cli['servers']}
    hook_path = sys.executable if RUNNING_FROZEN else os.path.abspath(__file__)
    hook_sha = ''
    if not RUNNING_FROZEN:
        try:
            hook_sha = hashlib.sha256(Path(hook_path).read_bytes()).hexdigest()[:16]
        except Exception:
            pass
    return {
        'version': MCP_DIAG_VERSION,
        'tool': raw_tool,
        'server_hint': _mcp_diag_server_hint(raw_tool),
        'cwd': cwd,
        'home': str(Path.home()),
        'platform': '%s %s' % (platform.system(), platform.release()),
        'python': sys.version.split()[0],
        'hook': '%s  (frozen=%s sha256 %s)' % (hook_path, RUNNING_FROZEN, hook_sha),
        'term_program': os.environ.get('TERM_PROGRAM') or '',
        'resolved': {
            'server': resolved[0], 'tool': resolved[1],
            'config': _mcp_diag_summarize(resolved[2]) if resolved[0] else None,
        },
        'known_servers': {
            name: '%s%s' % (server_sources.get(name, '?'),
                            ', AMBIGUOUS (config dropped)' if name in ambiguous else '')
            for name in servers
        },
        'hook_sources': hook_sources,
        'unread_sources': unread_sources,
        'matches': _mcp_diag_matches(raw_tool, hook_sources + unread_sources + [cli_group]),
        'vscode_server_logs': _mcp_diag_vscode_server_logs(
            _vscode_sanitize(_mcp_diag_server_hint(raw_tool))),
        'extension_providers': _mcp_diag_extension_providers(),
        'copilot_cli': copilot_cli,
        'vscode_settings': _mcp_diag_vscode_settings(),
        'error_log_tail': _mcp_diag_error_log_tail(),
    }


def _render_mcp_diagnostic(d):
    L = []

    def head(title):
        L.append('\n=== %s ===' % title)

    def kv(key, value):
        L.append('%-14s: %s' % (key, value))

    def sources(rows):
        for row in rows:
            if row['status'] == 'missing':
                L.append('  [missing] %s   (%s)' % (row['file'], row['source']))
                continue
            L.append('  %s   (%s, %s)' % (row['file'], row['source'], row['status']))
            for name, summary in row['servers'].items():
                L.append('      %-40s %s' % (name, summary))

    L.append('unbound-mcp-diag %s   tool=%s   server_hint=%s' % (
        d.get('version'), d.get('tool'), d.get('server_hint')))
    head('environment')
    for key in ('cwd', 'home', 'platform', 'python', 'hook', 'term_program'):
        kv(key, d.get(key))

    head('resolution replay')
    kv('resolved', json.dumps(d.get('resolved')))
    for name, source in (d.get('known_servers') or {}).items():
        L.append('  %-40s %s' % (name, source))

    head('servers VS Code actually started (logs/<session>/window*/mcpServer.<collection>.<server>.log)')
    for row in d.get('vscode_server_logs') or ['<no VS Code MCP server logs>']:
        L.append('  %s' % row)

    head('where a server matching the tool appears')
    matches = d.get('matches') or {}
    for kind in ('exact', 'near'):
        for row in matches.get(kind) or []:
            L.append('  %-5s %s   in %s (%s)   [%s]' % (
                kind, row['name'], row['source'], row['file'], row['cfg']))
    if not matches.get('exact') and not matches.get('near'):
        L.append('  <no matching server name in any source on disk>')

    head('sources the hook reads')
    sources(d.get('hook_sources') or [])

    head('sources the hook does NOT read')
    sources(d.get('unread_sources') or [])
    if not d.get('unread_sources'):
        L.append('  <none found>')

    head('VS Code extensions providing MCP servers')
    for row in d.get('extension_providers') or ['<none>']:
        L.append('  %s' % row)

    head('copilot mcp list --json')
    cli = d.get('copilot_cli') or {}
    kv('status', cli.get('status'))
    for name, summary in (cli.get('servers') or {}).items():
        L.append('  %-40s %s' % (name, summary))

    head('VS Code chat.mcp settings')
    for key, value in (d.get('vscode_settings') or {}).items():
        kv(key, value)

    head('hook error.log (mcp-related)')
    for line in d.get('error_log_tail') or []:
        L.append('  %s' % line)
    return '\n'.join(str(x) for x in L)


def _upload_mcp_diagnostic(payload, api_key):
    try:
        body = json.dumps({'diagnostic': payload, 'hook_source': 'copilot'})
    except Exception as exc:
        log_error('mcp diagnostic serialize failed: %s' % exc, 'mcp_server')
        return
    # In-process POST like _request_skill_sync: an argv carrying the key is
    # readable by any local process for as long as the upload runs.
    request = urllib.request.Request(
        '%s/v1/hooks/mcp-diagnostics' % UNBOUND_GATEWAY_URL,
        data=body.encode('utf-8'),
        headers={
            'Authorization': 'Bearer %s' % api_key,
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    opener = urllib.request.build_opener(_SkillSyncNoRedirects())
    try:
        with opener.open(request, timeout=MCP_DIAG_UPLOAD_TIMEOUT_SECONDS) as response:
            response.read(64 * 1024)
    except Exception as exc:
        log_error('mcp diagnostic upload failed: %s' % type(exc).__name__, 'mcp_server')


def _mcp_diag_reported_server(diagnostic, raw_tool):
    """The name to file the diagnostic under. One unambiguous on-disk match names the
    real server; otherwise fall back to the token parsed out of the tool name."""
    names = {row['name'] for row in ((diagnostic.get('matches') or {}).get('exact') or [])}
    if len(names) == 1:
        return names.pop()[:255]
    return _mcp_diag_server_hint(raw_tool)


def _run_mcp_diagnostic_cli():
    raw_tool = os.environ.get('UNBOUND_DIAG_TOOL') or ''
    cwd = os.environ.get('UNBOUND_DIAG_CWD') or None
    # pop, so `copilot mcp list` and curl don't inherit the key.
    api_key = os.environ.pop('UNBOUND_DIAG_API_KEY', None) or get_api_key()
    if not raw_tool or not api_key:
        return
    try:
        diagnostic = _build_mcp_diagnostic(raw_tool, cwd)
        report = _render_mcp_diagnostic(diagnostic)
    except Exception as exc:
        log_error('mcp diagnostic build failed: %s' % exc, 'mcp_server')
        return
    if len(report) > MCP_DIAG_MAX_REPORT_CHARS:
        report = report[:MCP_DIAG_MAX_REPORT_CHARS] + '\n… [report truncated]'
    _upload_mcp_diagnostic({
        'report': report,
        'server': _mcp_diag_reported_server(diagnostic, raw_tool),
        'cwd': cwd or '',
        'tool': raw_tool,
        'hook_source': 'copilot',
    }, api_key)


def _mcp_diag_stamp_path(server_hint, cwd):
    key = hashlib.sha256(('%s\x00%s' % (server_hint, cwd or '')).encode('utf-8', 'replace')).hexdigest()[:16]
    return MCP_DIAG_STAMP_DIR / key


def _mcp_diag_on_cooldown(server_hint, cwd):
    try:
        stamp = _mcp_diag_stamp_path(server_hint, cwd)
        return stamp.exists() and (time.time() - stamp.stat().st_mtime) < MCP_DIAG_COOLDOWN_SECONDS
    except Exception:
        return False


def _mcp_diag_mark_dispatched(server_hint, cwd):
    try:
        MCP_DIAG_STAMP_DIR.mkdir(parents=True, exist_ok=True)
        _mcp_diag_stamp_path(server_hint, cwd).write_text(str(int(time.time())), encoding='utf-8')
    except Exception:
        pass


def _dispatch_mcp_diagnostic(raw_tool, cwd, api_key):
    """Build + upload the diagnostic in a detached child so the config sweep stays
    off the blocking PreToolUse path. One per (server, cwd) per cooldown window."""
    if not raw_tool or not api_key:
        return
    server_hint = _mcp_diag_server_hint(raw_tool)
    if _mcp_diag_on_cooldown(server_hint, cwd):
        return
    if RUNNING_FROZEN:
        cmd = [sys.executable, 'mcp-diagnostic', os.environ.get('UNBOUND_HOOK_TOOL') or 'copilot']
    else:
        try:
            script = os.path.abspath(__file__)
        except Exception:
            return
        if not os.path.isfile(script):
            return
        cmd = [sys.executable, script, '--mcp-diagnostic']
    child_env = {'UNBOUND_DIAG_TOOL': raw_tool,
                 'UNBOUND_DIAG_CWD': cwd or '',
                 'UNBOUND_DIAG_API_KEY': api_key}
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
        _mcp_diag_mark_dispatched(server_hint, cwd)
    except Exception as exc:
        log_error('mcp diagnostic dispatch failed for %s: %s' % (raw_tool, exc), 'mcp_server')


def main():
    """Main entry point - read from stdin and process events."""
    global _cached_api_key
    api_key = get_api_key()
    _cached_api_key = api_key

    if len(sys.argv) > 1 and sys.argv[1] == '--sync-skills':
        _sync_skills_once(api_key)
        return

    if len(sys.argv) > 1 and sys.argv[1] == '--mcp-diagnostic':
        _run_mcp_diagnostic_cli()
        return

    try:
        input_data = sys.stdin.read().strip()

        if not input_data:
            _emit("{}")
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            _emit("{}")
            return

        event_name = _copilot_event_name(event)
        event = _normalize_cloud_event(event, event_name)

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if event_name == 'SessionStart':
            # None of it survives an ephemeral sandbox: the debounce cache is always empty, so
            # discovery reinstalls every session and synced skills land in a doomed workspace.
            if not RUNNING_CLOUD:
                _cleanup_skill_policy_state()
                _snapshot_copilot_skill_inventory(event)
                _dispatch_discovery()
                _dispatch_skills_sync(api_key)
            _emit("{}")
            return

        # Skill context rides UserPromptSubmit's additionalContext. Configs written
        # before that still register this event, so answer them until setup rewrites.
        if event_name == 'userPromptTransformed':
            _emit("{}")
            return

        if event_name in ('PreToolUse', 'preToolUse'):
            response = process_pre_tool_use(event, api_key)
            _emit(json.dumps(response))
            return

        if event_name == 'UserPromptSubmit':
            append_to_audit_log({
                'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
                'event': event,
            })
            # No repo gate here: conversation is never gated, but this call refreshes the policy cache so the session's first gated TOOL call is enforceable.
            response = process_user_prompt_submit(event, api_key)
            _emit(json.dumps(response) if response else "{}")
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
            exchange, forwarded_now, text_sig, prompts_now, turn_id = build_exchange_from_transcript(
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

                # The transcript's own id for the turn, so re-sending once the tokens
                # land addresses the row the first send created.
                turn_request_id = build_turn_request_id(session_id, turn_id)
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
                                              usage_index, pending_turns[-MAX_PENDING_TURNS:])
            elif still_pending != was_pending:
                # Nothing new this Stop, but some turns settled; drop just those.
                record_forwarded_tool_ids(wm_key, set(), None, None, None, still_pending)
            cleanup_old_logs()

        # Output required by Copilot hooks
        _emit("{}")

    except Exception as e:
        # Log errors but still output {} to not break Copilot
        log_error(f"Exception in main: {str(e)}", 'general')
        # Empty output is an allow, and every other cloud failure path denies.
        if RUNNING_CLOUD and os.environ.get('UNBOUND_HOOK_EVENT') == 'preToolUse':
            _emit(json.dumps(transform_response_for_copilot({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON,
                'additionalContext': 'The Unbound hook failed before it could evaluate this '
                                     'action. Do not retry or work around it. Stop and say so '
                                     'in the pull request.',
            })))
        else:
            _emit("{}")


if __name__ == '__main__':
    main()
