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
import shutil
import base64
import platform
import uuid
import urllib.request
from urllib.parse import unquote, urlparse


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
CODEX_HOME = Path(os.environ.get("CODEX_HOME", "").strip() or Path.home() / ".codex").expanduser()
CODEX_AUTH_PATH = CODEX_HOME / "auth.json"
# Shared with the cursor and claude-code hooks, so one probe serves all three.
IDENTITY_CACHE_PATH = Path.home() / ".unbound" / "identity.json"
CODEX_CONFIG_PATH = CODEX_HOME / "config.toml"
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
MANAGED_SKILLS_ROOT = Path.home() / '.agents' / 'skills'
UNBOUND_SKILL_PREFIX = 'unbound-'
UNBOUND_SKILL_MARKER = '.unbound-managed'
SKILL_POLICY_STATE_ROOT = Path.home() / '.unbound' / 'skill-policy' / 'codex'
SKILLS_SYNC_LOCK_PATH = SKILL_POLICY_STATE_ROOT / 'sync.lock'
SKILLS_SYNC_STALE_LOCK_SECONDS = 5 * 60
SKILLS_SYNC_TIMEOUT_SECONDS = 10
SKILL_POLICY_TOOL = 'codex'
SKILL_POLICY_API_KEY_ENV = 'UNBOUND_CODEX_API_KEY'
CODEX_SELECTED_SKILL_KIND = 'skills.selected_skill_instructions'
CODEX_SELECTED_SKILL_NAME_RE = re.compile(r'<name>\s*([^<\s][^<]*?)\s*</name>')
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
DISCOVERY_DISPATCH_TTL_SECONDS = 60
DISCOVERY_INSTALL_DIR = Path.home() / ".local" / "share" / "unbound"
DISCOVERY_INSTALL_SH = DISCOVERY_INSTALL_DIR / "install.sh"
DISCOVERY_INSTALL_PS1 = DISCOVERY_INSTALL_DIR / "install.ps1"
DISCOVERY_INSTALL_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.sh"
DISCOVERY_INSTALL_PS1_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.ps1"

DISCOVERY_INSTALL_SH_TTL_SECONDS = 24 * 3600
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"

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

_APPROVAL_MARKER_FILE = Path.home() / ".codex" / "hooks" / ".approval_pending"


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
    session = event.get('session_id')
    turn = event.get('turn_id') or event.get('prompt_id')
    return f'{session}:{turn}' if session and turn else ''


def _codex_selected_skill_slugs(payload):
    metadata = payload.get('internal_chat_message_metadata_passthrough')
    kinds = metadata.get('content_item_kinds') if isinstance(metadata, dict) else None
    if not isinstance(kinds, list) or CODEX_SELECTED_SKILL_KIND not in kinds:
        return set()
    names = []
    for part in payload.get('content') or []:
        text = part.get('text') if isinstance(part, dict) else None
        if isinstance(text, str):
            names.extend(CODEX_SELECTED_SKILL_NAME_RE.findall(text))
    return {
        name[len(UNBOUND_SKILL_PREFIX):]
        for name in names
        if name.startswith(UNBOUND_SKILL_PREFIX)
        and _skill_policy_valid_slug(name[len(UNBOUND_SKILL_PREFIX):])
    }


def _codex_output_text(payload):
    output = payload.get('output') if isinstance(payload, dict) else None
    if isinstance(output, str):
        return output
    if not isinstance(output, list):
        return ''
    return '\n'.join(
        part.get('text', '') for part in output
        if isinstance(part, dict) and isinstance(part.get('text'), str)
    )


def _codex_skill_slugs_from_output(command, output):
    if not isinstance(command, str) or not isinstance(output, str):
        return set()
    if len(output.encode('utf-8', 'replace')) > 2 * 1024 * 1024:
        return set()
    observed = set()
    for directory in _managed_skill_dirs():
        slug = _managed_skill_slug(directory)
        skill_path = directory / 'SKILL.md'
        if not slug or str(skill_path) not in command:
            continue
        if skill_path.is_symlink():
            continue
        try:
            content = skill_path.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            continue
        output_body = output.strip()
        output_size = len(output_body.encode('utf-8'))
        content_size = len(content.encode('utf-8'))
        if content in output or (
            output_size >= 128
            and output_size * 10 >= content_size * 9
            and content.startswith(output_body)
        ):
            observed.add(slug)
    return observed


def _codex_completed_command_skill_slugs(payload):
    if not isinstance(payload, dict) or payload.get('type') != 'item_completed':
        return set()
    item = payload.get('item')
    if not isinstance(item, dict) or item.get('type') != 'CommandExecution':
        return set()
    command = item.get('command')
    if isinstance(command, list):
        command = ' '.join(str(part) for part in command)
    output = item.get('aggregated_output') or item.get('stdout') or item.get('formatted_output')
    return _codex_skill_slugs_from_output(command, output)


def _codex_session_skill_slugs(transcript):
    found = set()
    calls = {}
    try:
        with open(transcript, 'rb') as transcript_file:
            for raw in transcript_file:
                try:
                    entry = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(entry, dict):
                    continue
                payload = entry.get('payload')
                if not isinstance(payload, dict):
                    continue
                if entry.get('type') == 'event_msg':
                    found.update(_codex_completed_command_skill_slugs(payload))
                    continue
                if entry.get('type') != 'response_item':
                    continue
                payload_type = payload.get('type')
                if payload_type == 'message' and payload.get('role') == 'user':
                    found.update(_codex_selected_skill_slugs(payload))
                    continue
                if payload_type in ('custom_tool_call', 'function_call'):
                    call_id = payload.get('call_id')
                    command = payload.get('input') if payload_type == 'custom_tool_call' else payload.get('arguments')
                    if isinstance(call_id, str) and isinstance(command, str) and 'SKILL.md' in command:
                        calls[call_id] = command
                    continue
                if payload_type not in ('custom_tool_call_output', 'function_call_output'):
                    continue
                call_id = payload.get('call_id')
                command = calls.pop(call_id, '') if isinstance(call_id, str) else ''
                if command:
                    found.update(_codex_skill_slugs_from_output(command, _codex_output_text(payload)))
    except OSError:
        pass
    return found


def _skill_policy_loaded_facts(event):
    transcript = event.get('transcript_path')
    if not isinstance(transcript, str) or not transcript or transcript == 'undefined':
        return {'loaded': set(), 'session_count': 0}
    loaded = set()
    session_names = set()
    try:
        lines = _skill_policy_transcript_tail(transcript)
        outputs = {}
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
            payload = entry.get('payload')
            payload_type = payload.get('type') if isinstance(payload, dict) else None
            if entry_type == 'compacted' or (entry_type == 'event_msg' and payload_type == 'context_compacted'):
                in_window = False
                continue
            if entry_type == 'event_msg':
                if payload_type == 'task_started':
                    turns += 1
                    if turns > SKILL_LOADED_WINDOW:
                        in_window = False
                    continue
                found = _codex_completed_command_skill_slugs(payload)
                session_names.update(found)
                if in_window:
                    loaded.update(found)
                continue
            if entry_type != 'response_item' or not isinstance(payload, dict):
                continue
            if payload_type in ('custom_tool_call_output', 'function_call_output'):
                call_id = payload.get('call_id')
                text = _codex_output_text(payload)
                if isinstance(call_id, str) and text:
                    outputs[call_id] = text
                continue
            if payload_type == 'message' and payload.get('role') == 'user':
                found = _codex_selected_skill_slugs(payload)
            elif payload_type == 'custom_tool_call' and payload.get('status') == 'completed':
                command = payload.get('input')
                call_id = payload.get('call_id')
                output = outputs.get(call_id, '') if isinstance(call_id, str) else ''
                found = _codex_skill_slugs_from_output(command, output)
            elif payload_type == 'function_call':
                command = payload.get('arguments')
                call_id = payload.get('call_id')
                output = outputs.get(call_id, '') if isinstance(call_id, str) else ''
                found = _codex_skill_slugs_from_output(command, output)
            else:
                continue
            session_names.update(found)
            if in_window:
                loaded.update(found)
    except OSError:
        pass
    session_names.update(_codex_session_skill_slugs(transcript))
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



def _emit(text: str):
    """Write a hook response line to stdout, treating a closed reader pipe as
    a benign no-op. The host may close the read end (timeout, cancel, session
    end, blocked approval-poll) before we flush — that is not a hook error."""
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


def get_repo_policies() -> List[Dict]:
    """Repo-scope policies from cache, [] if absent; a stale cache still applies."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return []
    policies = cache.get('repo_policies')
    return policies if isinstance(policies, list) else []


def save_policy_cache(tools_to_check: Optional[List[str]] = None, policy_check_failure_action: Optional[str] = None, repo_policies: Optional[List[Dict]] = None, unbound_attribution_enabled: Optional[bool] = None):
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
        if isinstance(unbound_attribution_enabled, bool):
            cache['unbound_attribution_enabled'] = unbound_attribution_enabled
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
    # Claude-parity — additionalContext feeds the model, while the user sees
    # user_notice when the gateway sends one (a skill instruction's admin
    # message), else the same text.
    additional_context = api_response.get('additionalContext', '')
    if additional_context:
        return {
            'hookSpecificOutput': {
                'hookEventName': 'UserPromptSubmit',
                'additionalContext': additional_context,
            },
            'systemMessage': api_response.get('user_notice') or additional_context,
        }

    return {}


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
_MCP_CACHE_CODING_TOOL_NAMES = frozenset({'codex'})
_MCP_CACHE_CODING_TOOL_PREFIXES = ()
_UNBOUND_CODING_TOOL = 'Codex'


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


def _codex_account_config() -> Dict:
    """config.toml's credential store and the base URL Codex sends model traffic to."""
    try:
        raw = CODEX_CONFIG_PATH.read_text(encoding='utf-8')
        try:
            import tomllib
            data = tomllib.loads(raw)
        except ImportError:
            data = _codex_account_config_regex(raw)
    except Exception:
        return {}
    profiles = data.get('profiles') if isinstance(data.get('profiles'), dict) else {}
    profile = profiles.get(data.get('profile')) if isinstance(data.get('profile'), str) else None
    profile = profile if isinstance(profile, dict) else {}
    provider = profile.get('model_provider') or data.get('model_provider')
    providers = data.get('model_providers') if isinstance(data.get('model_providers'), dict) else {}
    chosen = providers.get(provider) if isinstance(provider, str) else None
    base_url = ((chosen.get('base_url') if isinstance(chosen, dict) else None)
                or profile.get('openai_base_url') or data.get('openai_base_url'))
    store = data.get('cli_auth_credentials_store')
    return {'base_url': base_url if isinstance(base_url, str) else None,
            'credentials_store': store if isinstance(store, str) else None}


def _codex_account_config_regex(raw: str) -> Dict:
    def section(name: str) -> Optional[str]:
        m = re.search(r'^\s*\[%s\][^\n]*\n(.*?)(?=^\s*\[|\Z)' % name, raw, re.M | re.S)
        return m.group(1) if m else None

    def values(body: str, keys) -> Dict:
        found = {}
        for key in keys:
            m = re.search(rf'^\s*{key}\s*=\s*["\']([^"\']*)["\']', body, re.M)
            if m:
                found[key] = m.group(1)
        return found

    data = values(re.split(r'^\s*\[', raw, maxsplit=1, flags=re.M)[0],
                  ('model_provider', 'openai_base_url', 'cli_auth_credentials_store', 'profile'))
    profile_name = data.get('profile')
    body = section(r'profiles\.["\']?%s["\']?' % re.escape(profile_name)) if profile_name else None
    profile = values(body, ('model_provider', 'openai_base_url')) if body else {}
    if profile:
        data['profiles'] = {profile_name: profile}
    provider = profile.get('model_provider') or data.get('model_provider')
    body = section(r'model_providers\.["\']?%s["\']?' % re.escape(provider)) if provider else None
    url = values(body, ('base_url',)) if body else {}
    if url:
        data['model_providers'] = {provider: url}
    return data


def _codex_gateway_host(base_url: Optional[str]) -> Optional[str]:
    """The host Codex sends requests to. Same rule as the Claude Code hook, plus OpenAI itself:
    shared hosts would put every developer in one fake account."""
    try:
        host = (urlparse((base_url or '').strip()).hostname or '').lower()
    except ValueError:
        return None
    shared = (host == urlparse(UNBOUND_GATEWAY_URL).hostname or host in ('getunbound.ai', 'openai.com')
              or host.endswith(('.getunbound.ai', '.openai.com'))
              or host in ('localhost', '0.0.0.0', '::1') or host.startswith('127.'))
    return host if host and not shared else None


def read_account_identity() -> Dict:
    org_id = None
    plan = None
    auth_mode = None
    email = None
    email_domain = None
    reason = None
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
            if not claims:
                reason = 'id_token_unreadable'
            auth_claim = claims.get('https://api.openai.com/auth') or {}
            if isinstance(auth_claim, dict):
                org_id = _codex_org_id(auth_claim)
                plan = auth_claim.get('chatgpt_plan_type') or None
            email = claims.get('email') or None
            email_domain = _email_domain(email)
        elif auth_mode == 'subscription':
            reason = 'no_id_token'
    except FileNotFoundError:
        reason = 'auth_json_missing'
    except Exception:
        reason = 'auth_json_unreadable'
    if not org_id and not email:
        try:
            config = _codex_account_config()
        except Exception:
            config = {}
        store = config.get('credentials_store') or ''
        if auth_mode == 'api_key':
            reason = 'api_key'
        elif reason in (None, 'auth_json_missing') and (os.environ.get('OPENAI_API_KEY') or os.environ.get('CODEX_API_KEY')):
            auth_mode, reason = 'api_key', 'api_key_env'
        elif reason in (None, 'auth_json_missing', 'no_id_token') and store in ('keyring', 'auto', 'ephemeral'):
            reason = 'credentials_' + store
        elif reason is None:
            reason = 'no_account_in_auth_json'
        org_id = _codex_gateway_host(config.get('base_url') or os.environ.get('OPENAI_BASE_URL'))
    identity = {
        'org_id': org_id,
        'plan': plan,
        'auth_mode': auth_mode,
        'user_email': email,
        'email_domain': email_domain,
    }
    if reason:
        identity['account_reason'] = reason
    return identity


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

def build_account_identity(probe: bool = True) -> Dict:
    identity = read_account_identity()
    try:
        serial = _device_serial(probe=probe)
        if serial:
            identity['device_serial'] = serial
    except Exception:
        pass
    return identity


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """PreToolUse entry point - DO NOT LOG. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for apply_patch when no policy covers it."""
    gate = _repo_gate_evaluate(event)
    if gate:
        return transform_response_for_codex({
            'decision': 'deny',
            'reason': _repo_gate_block_reason(gate['repo'], gate.get('trace_id')),
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
    _attach_installed_skill_facts(metadata, event)

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
        # The pre-tool path reads the serial cache only; the prompt event probes.
        'account_identity': build_account_identity(probe=False),
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
            unbound_trace_id = marker_data.get('unboundTraceId')
            footer = _attribution_footer(unbound_trace_id) if unbound_trace_id else ''
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return transform_response_for_codex({'decision': 'allow'})
            elif result == 'deny':
                return transform_response_for_codex({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This command was denied via Slack.' + footer,
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
                    'reason': timeout_reason + footer,
                    'additionalContext': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            footer = _attribution_footer() if get_unbound_attribution_enabled() else ''
            return transform_response_for_codex({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON + footer,
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

    if (
        api_response.get('decision') == 'deny'
        and api_response.get('inject_skills')
        and api_response.get('additionalContext')
    ):
        _claim_skill_injection_turn(event)
    _apply_skill_lifecycle_actions(api_response, api_key)
    return transform_response_for_codex(api_response)


def process_user_prompt_submit(event: Dict, api_key: str) -> Dict:
    """Process UserPromptSubmit event for policy checking. Also refreshes the policy cache, which is what makes the session's FIRST gated tool call enforceable: the gate never calls the network."""
    session_id = event.get('session_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    metadata = {}
    cwd = event.get('cwd')
    if isinstance(cwd, str) and cwd:
        metadata['cwd'] = cwd
    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'codex',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else [],
        'pre_tool_use_data': {'tool_name': '', 'command': '', 'metadata': metadata},
    }
    _attach_installed_skill_facts(request_body['pre_tool_use_data']['metadata'], event)
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    if (
        isinstance(api_response, dict)
        and api_response.get('decision') not in ('deny', 'block')
        and api_response.get('inject_skills')
        and api_response.get('additionalContext')
    ):
        _claim_skill_injection_turn(event)
    _apply_skill_lifecycle_actions(api_response, api_key)
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


# --- Repository-scope gate: blocks writes, git write subcommands and shell writes in repos outside the org's allowed scope, decided on-device and fail-open ---

# Write tools, git write subcommands and shell writes only; apply_patch is Codex's only write tool, and conversation and every other shell command (ls, cat, npm test) are ungated.
_REPO_GATE_WRITE_TOOLS = frozenset({'apply_patch'})
_REPO_GATE_SHELL_TOOLS = frozenset({'Bash'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)


_CODEX_SHELL_ALIASES = frozenset({'exec_command', 'shell', 'local_shell'})


def _canonical_codex_tool(tool_name: Optional[str]) -> str:
    """Codex spells its shell tool exec_command / shell; the gate speaks Bash."""
    return 'Bash' if tool_name in _CODEX_SHELL_ALIASES else (tool_name or '')


def _repo_gate_command(tool_input: Optional[Dict]) -> Optional[str]:
    """The shell command a Bash call carries; exec_command spells it `cmd`."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get('command')
    if command is None:
        command = tool_input.get('cmd')
    if isinstance(command, list):
        command = ' '.join(str(part) for part in command)
    return command if isinstance(command, str) else None


def _repo_gate_applies(tool_name, command):
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it runs a git write or writes a file."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_write_command(command) or _is_shell_write_command(command)
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
        command = _repo_gate_command(tool_input)
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


def _repo_gate_block_reason(repo: str, trace_id: Optional[str] = None) -> str:
    reason = (
        'Blocked by organization policy. "%s" is outside your organization\'s '
        'allowed repository scope.' % repo
    )
    return reason + _attribution_footer(trace_id) if trace_id else reason


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
    """Verdict for one tool call: None allows, else deny. Never raises."""
    try:
        tool_name = _canonical_codex_tool(event.get('tool_name'))
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
        if gate and get_unbound_attribution_enabled():
            gate['trace_id'] = str(uuid.uuid4())
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
                'content_hash': _skill_content_hash(path),
            })
    except Exception:
        return []
    return entries


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
# Set by set -a: '1' on, '' off, and a substitution when it may be either; plain assignments are then exported.
_TRANSFER_ALLEXPORT = '\0allexport'
# Set by set -e, held as allexport is: a command that fails then ends the shell.
_TRANSFER_ERREXIT = '\0errexit'
# Set by set -o pipefail, held as allexport is: a pipeline fails when a command in it fails.
_TRANSFER_PIPEFAIL = '\0pipefail'
# Stands in for a substitution's output inside a word, so no host is read from it.
_TRANSFER_SUBSTITUTED = '\0'
# Added to a call's ssh options when the config it reads isn't known, so ssh -G and DNS never run for it.
_TRANSFER_CONFIG_UNKNOWN = ('-F', _TRANSFER_SUBSTITUTED)
# Whether the hook runs on Windows, where scp reads a one-letter X: as a drive.
_TRANSFER_WINDOWS = os.name == 'nt'
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
_TRANSFER_CURL_PROXIES = {'-x': '', '--proxy': '', '--proxy1.0': '', '--preproxy': '', '--socks4': 'socks4',
                          '--socks4a': 'socks4a', '--socks5': 'socks5', '--socks5-hostname': 'socks5h'}
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
    '--trace-config --unix-socket --upload-file --url --url-query --user --user-agent --variable --write-out '
    '--proxy1.0 --krb4 --ech --httpsig-algo --httpsig-headers --httpsig-key --httpsig-keyid --ip-tos --knownhosts '
    '--sigalgs --ssl-sessions --upload-flags').split())
# curl 8.5's long options without the --, the last curl that reads a prefix as the one option it starts.
_TRANSFER_CURL_LONG_OPTIONS = frozenset((
    'abstract-unix-socket alpn alt-svc anyauth append aws-sigv4 basic buffer ca-native cacert capath cert cert-status '
    'cert-type ciphers clobber compressed compressed-ssh config connect-timeout connect-to continue-at cookie '
    'cookie-jar create-dirs create-file-mode crlf crlfile curves data data-ascii data-binary data-raw data-urlencode '
    'delegation digest disable disable-eprt disable-epsv disallow-username-in-url dns-interface dns-ipv4-addr '
    'dns-ipv6-addr dns-servers doh-cert-status doh-insecure doh-url dump-header egd-file engine eprt epsv '
    'etag-compare etag-save expect100-timeout fail fail-early fail-with-body false-start form form-escape form-string '
    'ftp-account ftp-alternative-to-user ftp-create-dirs ftp-method ftp-pasv ftp-port ftp-pret ftp-skip-pasv-ip '
    'ftp-ssl ftp-ssl-ccc ftp-ssl-ccc-mode ftp-ssl-control ftp-ssl-reqd get globoff happy-eyeballs-timeout-ms '
    'haproxy-clientip haproxy-protocol head header help hostpubmd5 hostpubsha256 hsts http0.9 http1.0 http1.1 http2 '
    'http2-prior-knowledge http3 http3-only ignore-content-length include insecure interface ipfs-gateway ipv4 ipv6 '
    'json junk-session-cookies keepalive keepalive-time key key-type krb krb4 libcurl limit-rate list-only local-port '
    'location location-trusted login-options mail-auth mail-from mail-rcpt mail-rcpt-allowfails manual max-filesize '
    'max-redirs max-time metalink negotiate netrc netrc-file netrc-optional next noproxy npn ntlm ntlm-wb '
    'oauth2-bearer output output-dir parallel parallel-immediate parallel-max pass path-as-is pinnedpubkey post301 '
    'post302 post303 preproxy progress-bar progress-meter proto proto-default proto-redir proxy proxy-anyauth '
    'proxy-basic proxy-ca-native proxy-cacert proxy-capath proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile '
    'proxy-digest proxy-header proxy-http2 proxy-insecure proxy-key proxy-key-type proxy-negotiate proxy-ntlm '
    'proxy-pass proxy-pinnedpubkey proxy-service-name proxy-ssl-allow-beast proxy-ssl-auto-client-cert '
    'proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword proxy-tlsuser proxy-tlsv1 proxy-user proxy1.0 '
    'proxytunnel pubkey quote random-file range rate raw referer remote-header-name remote-name remote-name-all '
    'remote-time remove-on-error request request-target resolve retry retry-all-errors retry-connrefused retry-delay '
    'retry-max-time sasl-authzid sasl-ir service-name sessionid show-error silent socks4 socks4a socks5 socks5-basic '
    'socks5-gssapi socks5-gssapi-nec socks5-gssapi-service socks5-hostname speed-limit speed-time ssl ssl-allow-beast '
    'ssl-auto-client-cert ssl-no-revoke ssl-reqd ssl-revoke-best-effort sslv2 sslv3 stderr styled-output '
    'suppress-connect-headers tcp-fastopen tcp-nodelay telnet-option test-event tftp-blksize tftp-no-options '
    'time-cond tls-max tls13-ciphers tlsauthtype tlspassword tlsuser tlsv1 tlsv1.0 tlsv1.1 tlsv1.2 tlsv1.3 '
    'tr-encoding trace trace-ascii trace-config trace-ids trace-time unix-socket upload-file url url-query use-ascii '
    'user user-agent variable verbose version wdebug write-out xattr').split())
# Bodies curl sends to every URL of a request; each -T or --upload-file goes to one URL instead, in order.
_TRANSFER_CURL_UPLOADS = frozenset({'-F', '--form', '--form-string', '--json'})
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
    '--report-speed --progress --use-askpass --bind-dns-address --dns-servers --dot-style --http-passwd '
    '--input-metalink --metalink-index --no --preferred-location --proxy-passwd --start-pos').split())
# GNU wget's long options without the --, each --no- form included, for getopt's reading of a prefix as one option.
_TRANSFER_WGET_LONG_OPTIONS = frozenset((
    'accept accept-regex adjust-extension append-output ask-password auth-no-challenge background backup-converted '
    'backups base bind-address bind-dns-address body-data body-file ca-certificate ca-directory cache certificate '
    'certificate-type check-certificate ciphers clobber compression config connect-timeout content-disposition '
    'content-on-error continue convert-file-only convert-links cookies crl-file cut-dirs debug default-page '
    'delete-after directories directory-prefix dns-cache dns-servers dns-timeout domains dont-remove-listing '
    'dot-style egd-file exclude-directories exclude-domains execute follow-ftp follow-tags force-directories '
    'force-html ftp-password ftp-stmlf ftp-user ftps-clear-data-connection ftps-fallback-to-ftp ftps-implicit '
    'ftps-resume-ssl glob header help host-directories hsts hsts-file html-extension htmlify http-keep-alive '
    'http-passwd http-password http-user https-only if-modified-since ignore-case ignore-length ignore-tags '
    'include-directories inet4-only inet6-only input-file input-metalink iri keep-badhash keep-session-cookies level '
    'limit-rate load-cookies local-encoding max-redirect metalink-index metalink-over-http method mirror netrc no '
    'no-adjust-extension no-ask-password no-auth-no-challenge no-background no-backup-converted no-backups no-cache '
    'no-check-certificate no-clobber no-config no-content-disposition no-content-on-error no-continue '
    'no-convert-file-only no-convert-links no-cookies no-debug no-delete-after no-directories no-dns-cache '
    'no-follow-ftp no-force-directories no-force-html no-ftp-stmlf no-ftps-clear-data-connection '
    'no-ftps-fallback-to-ftp no-ftps-implicit no-ftps-resume-ssl no-glob no-host-directories no-hsts '
    'no-html-extension no-htmlify no-http-keep-alive no-https-only no-if-modified-since no-ignore-case '
    'no-ignore-length no-inet4-only no-inet6-only no-iri no-keep-badhash no-keep-session-cookies '
    'no-metalink-over-http no-mirror no-netrc no-no-clobber no-no-config no-no-parent no-page-requisites no-parent '
    'no-passive-ftp no-preserve-permissions no-protocol-directories no-proxy no-quiet no-random-wait no-recursive '
    'no-relative no-remove-listing no-report-speed no-restrict-file-names no-retr-symlinks no-retry-connrefused '
    'no-retry-on-host-error no-save-headers no-server-response no-show-progress no-span-hosts no-spider '
    'no-strict-comments no-timestamping no-trust-server-names no-unlink no-use-server-timestamps no-verbose '
    'no-warc-cdx no-warc-compression no-warc-digests no-warc-keep-log no-wdebug no-xattr output-document output-file '
    'page-requisites parent passive-ftp password pinnedpubkey post-data post-file prefer-family preferred-location '
    'preserve-permissions private-key private-key-type progress protocol-directories proxy proxy-passwd '
    'proxy-password proxy-user proxy__compat quiet quota random-file random-wait read-timeout recursive referer '
    'regex-type reject reject-regex rejected-log relative remote-encoding remove-listing report-speed '
    'restrict-file-names retr-symlinks retry-connrefused retry-on-host-error retry-on-http-error save-cookies '
    'save-headers secure-protocol server-response show-progress span-hosts spider start-pos strict-comments timeout '
    'timestamping tries trust-server-names unlink use-askpass use-server-timestamps user user-agent verbose version '
    'wait waitretry warc-cdx warc-compression warc-dedup warc-digests warc-file warc-header warc-keep-log '
    'warc-max-size warc-tempdir wdebug xattr').split())
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


def _transfer_executable(name: str) -> Optional[str]:
    """The program's absolute path from PATH's absolute folders; Windows would otherwise run a copy planted in this
    process's working folder first, whatever folder the child is given. None when there is none."""
    for folder in os.environ.get('PATH', '').split(os.pathsep):
        path = os.path.join(folder, name + ('.exe' if os.name == 'nt' else ''))
        if os.path.isabs(folder) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


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
        program = _transfer_executable(argv[0])
        if program is None:
            return None
        result = subprocess.run([program] + argv[1:], cwd=folder, capture_output=True,
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


_TRANSFER_ANSI_C = {'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
                    'v': '\v', '\\': '\\', "'": "'", '"': '"', '?': '?'}


def _transfer_ansi_c(text: str, i: int) -> Optional[tuple]:
    """(the text of a bash $'…' word whose body starts at i, its escapes decoded, the index of its closing quote); None
    when it isn't closed. A NUL ends the text, as in bash."""
    out, ended = [], False
    while i < len(text):
        ch, i = text[i], i + 1
        if ch == "'":
            return ''.join(out), i - 1
        if ch == '\\' and i < len(text):
            escape, i = text[i], i + 1
            digits = {'x': 2, 'u': 4, 'U': 8}.get(escape)
            hexa = re.match(r'[0-9a-fA-F]{1,%d}' % digits, text[i:]) if digits else None
            octal = re.match(r'[0-7]{1,3}', text[i - 1:]) if escape in '01234567' else None
            if escape in _TRANSFER_ANSI_C:
                ch = _TRANSFER_ANSI_C[escape]
            elif octal:
                ch, i = chr(int(octal.group(), 8) & 0xff), i - 1 + len(octal.group())
            elif hexa and int(hexa.group(), 16) <= 0x10ffff:
                ch, i = chr(int(hexa.group(), 16)), i + len(hexa.group())
            elif escape == 'c' and i < len(text):
                ch, i = ('\x7f' if text[i] == '?' else chr(ord(text[i]) & 0x1f)), i + 1
            else:
                ch = '\\' + escape
        ended = ended or '\0' in ch
        out += [] if ended else [ch]
    return None


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
        if ch == '$' and text[i + 1:i + 2] == '"':
            self.i, self.quote, self.in_word = i + 1, '"', True  # $"…" is "…" translated, which keeps it as written
        elif ch == '$' and text[i + 1:i + 2] == "'":
            found = _transfer_ansi_c(text, i + 2)
            if found is None:
                return False
            for c in found[0]:
                # A character the walker uses as a mark stands for one not known.
                self.word += _TRANSFER_SUBSTITUTED if c < '\x06' else self._literal(c)
            self.in_word, self.i = True, found[1]
        elif ch in '\'"':
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
        if op in ('<&', '>&') and re.fullmatch(r'\d+-?|-', target):
            self.io.append((to, int(target.rstrip('-')) if target != '-' else 'null'))
            if target[:-1].isdigit() and target.endswith('-'):
                self.io.append((int(target[:-1]), 'null'))  # <&N- moves N, which is then closed
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
    """Where a cd goes as the shell expands its folder, HOME for none; None when not known, including a
    relative folder that CDPATH may find somewhere else first."""
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
    shell['pipe'] = {'before': before, 'prior': shell['status'], 'runs': runs, 'negate': False, 'leading': False,
                     'statuses': []}


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
        # Under pipefail the pipeline leaves its last non-zero status: one command that surely fails fails it, and
        # otherwise one whose status isn't known leaves it unknown. When pipefail itself isn't known, the two readings
        # must agree.
        statuses, pipefail = pipe['statuses'] + [status], shell['vars'].get(_TRANSFER_PIPEFAIL, ('', True))[0]
        failing = 1 if 1 in statuses else None if None in statuses else status
        status = status if not pipefail else failing if pipefail == '1' or failing == status else None
        status = {0: 1, 1: 0}.get(status) if pipe['negate'] else status
        skipped = {'&&': 1, '||': 0}.get(pipe['before'])
        if pipe['prior'] is None and skipped is not None and status != skipped:
            status = None
    shell['status'] = status


def _transfer_finish(after: str, shell: Dict) -> None:
    """End a pipeline element: the pipeline ends unless a | follows, and a backgrounded list runs in a subshell."""
    if after == '|':
        shell['pipe']['statuses'].append(shell['status'])  # for pipefail
    else:
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
                   'jumped': None, 'cond': kind in ('if', 'while', 'until'),
                   'exempt': _transfer_exempt(shell) or shell['pipe']['negate'] or _transfer_ends_list(head, shell),
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
            name = rest[0] if keyword in ('for', 'select') and rest else ''
            if re.fullmatch(_TRANSFER_NAME, name) and loop['iterates'] is not False:
                # Each pass sets the name, exported if it was or allexport is on.
                exported = _transfer_auto_export(shell, _transfer_variable(shell, name)[1])
                shell['vars'][name] = (_TRANSFER_SUBSTITUTED, exported)
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
        frames[-1]['cond'] = keyword == 'elif'  # a then or do starts the body, and an elif another condition
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
        # Only the word in command position runs; an argument that names break, eval or a function does not.
        lead = [w for w in words if w not in _TRANSFER_KEYWORDS and not _transfer_is_assignment(w)]
        while lead[:1] in (['command'], ['builtin']):
            lead = lead[1:]
        if not lead:
            continue
        word, count = lead[0], lead[1] if len(lead) > 1 else '1'
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
                if frame['kind'] == '(':
                    _transfer_errexit(after, shell)  # a subshell that fails is a command that fails


def _transfer_builtin(program: str, args: List[str], shell: Dict) -> None:
    """Apply an export, unset or declaration, or a command made only of assignments (program ''), to the commands
    after it."""
    if program == 'unset':
        _transfer_unset(args, shell)
    elif program in _TRANSFER_SETS:
        _transfer_set(program, args, shell)
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
            shell['vars'][name] = (value, _transfer_auto_export(shell, _transfer_variable(shell, name)[1]))


_TRANSFER_SETS = ('set', 'setopt', 'unsetopt')


_TRANSFER_SET_OPTIONS = {'allexport': _TRANSFER_ALLEXPORT, 'errexit': _TRANSFER_ERREXIT, 'pipefail': _TRANSFER_PIPEFAIL}
_TRANSFER_SET_FLAGS = {'a': 'allexport', 'e': 'errexit'}


def _transfer_set(program: str, args: List[str], shell: Dict) -> None:
    """set -a or -e, -o allexport or errexit, or a cluster with a or e turns the option on, and the + forms off. setopt,
    unsetopt and zsh's spellings such as all_export leave it unknown, as bash has none of them."""
    i = 0
    while program == 'set' and i < len(args) and args[i][:1] in ('-', '+') and args[i] not in ('-', '--', '+'):
        arg, i = args[i], i + 1
        for flag in arg[1:]:
            name = (args[i] if i < len(args) else '') if flag == 'o' else _TRANSFER_SET_FLAGS.get(flag, '')
            i += flag == 'o'
            if name in _TRANSFER_SET_OPTIONS:
                shell['vars'][_TRANSFER_SET_OPTIONS[name]] = ('1' if arg[0] == '-' else '', True)
            else:
                _transfer_forget(shell, set(_transfer_zsh_options(name)))
    if program != 'set':
        _transfer_forget(shell, {key for arg in args for key in _transfer_zsh_options(arg)})


def _transfer_zsh_options(name: str) -> List[str]:
    """The options a zsh spelling such as all_export or noerrexit names, ignoring case and underscores."""
    name = name.lower().replace('_', '')
    return [key for option, key in _TRANSFER_SET_OPTIONS.items() if name in (option, 'no' + option)]


def _transfer_auto_export(shell: Dict, exported) -> Optional[bool]:
    """Whether a variable assigned now is exported: always while allexport is on, maybe while it may be, else as
    before."""
    allexport = shell['vars'].get(_TRANSFER_ALLEXPORT, ('', True))[0]
    if exported is True or exported in _TRANSFER_LENT or allexport == '':
        return exported
    return True if allexport == '1' else None


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
        shell['vars'][name] = (value if eq else current, True if on else False if off else
                               _transfer_auto_export(shell, exported) if eq else exported)


def _transfer_stdin_script(program: str, args: List[str]) -> Optional[List[str]]:
    """The positional parameters of a shell that reads its script from stdin, with no -c string and no script file;
    None for any other command."""
    if program not in _TRANSFER_SHELLS:
        return None
    i, letters, _, end = _transfer_shell_flags(args)
    if 'c' in letters:
        return None
    return args[i:] if 's' in letters or end == '-' else [] if i >= len(args) else None  # else a script file


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
    """The heredoc or here-string text a call's stdin reads, as its pipes and redirections set it, a <&N taking the text
    on N; None otherwise."""
    fds = {}
    for piped_in, _, redirections in reversed(layers):
        fds[0] = None if piped_in else fds.get(0)
        for fd, value in redirections:
            fds[fd] = value if isinstance(value, _TransferStdin) else fds.get(value) if isinstance(value, int) else None
    return fds[0].text if fds.get(0) is not None else None


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


_TRANSFER_SHELL_FLAGS = {'a': 'allexport', 'e': 'errexit', 'n': 'noexec'}
_TRANSFER_ZSH_SPELLINGS = {'allexport': 'allexport', 'noallexport': 'allexport', 'errexit': 'errexit',
                           'noerrexit': 'errexit', 'exec': 'noexec', 'noexec': 'noexec', 'pipefail': 'pipefail',
                           'nopipefail': 'pipefail'}


def _transfer_shell_flags(args: List[str]) -> tuple:
    """A shell's startup options as bash reads them: (where its operands start, the option letters given, the options
    set as {name: '1' on, '' off, or a substitution when not known}, the - or -- that ended them, else '')."""
    i, letters, options = 0, set(), {}
    while i < len(args):
        arg, i = args[i], i + 1
        if arg in ('-', '--'):
            return i, letters, options, arg
        if arg in ('--rcfile', '--init-file'):
            i += 1
        elif not (len(arg) > 1 and arg[0] in '-+'):
            return i - 1, letters, options, ''
        elif not arg.startswith('--'):
            for flag in arg[1:]:
                letters.add(flag)
                # -o and -O take the word after the cluster, as in -eo pipefail.
                name = (args[i] if i < len(args) else '') if flag in 'oO' else _TRANSFER_SHELL_FLAGS.get(flag, '')
                i += flag in 'oO'
                spelled = _TRANSFER_ZSH_SPELLINGS.get(name.lower().replace('_', ''))
                if flag != 'O' and (name in _TRANSFER_SHELL_FLAGS.values() or name == 'pipefail'):
                    options[name] = '1' if arg[0] == '-' else ''
                elif flag != 'O' and spelled:
                    options[spelled] = _TRANSFER_SUBSTITUTED  # zsh's spellings, which bash rejects
    return i, letters, options, ''


def _transfer_shell_string(program: str, args: List[str]) -> Optional[str]:
    """The command string `sh -c` or `powershell -Command` runs; None for any other command."""
    if program in _TRANSFER_SHELLS:
        i, letters = _transfer_shell_flags(args)[:2]
        return args[i] if 'c' in letters and i < len(args) else None
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
        # A body called in an && or || list but as its last command, or behind a !, runs with set -e ignored.
        exempt = after in ('&&', '||') or shell['pipe']['negate'] or _transfer_exempt(shell)
        shell['exempt'] = shell.get('exempt', 0) + exempt
        _transfer_call(known, layer, subshell, shell, depth)  # looked up first: the body may remove the function
        shell['exempt'] -= exempt
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
        options = set(_TRANSFER_SET_OPTIONS.values())
        _transfer_forget(shell, {n for n in shell['vars'] if not n.startswith('\0')} | {''} | options)
        shell['vars'][_TRANSFER_UNKNOWN_ENV] = (None, None)
        # It may also redefine any function, so each one known may no longer run as written.
        shell['functions'] = {name: (known[0], True) for name, known in shell['functions'].items()}
    if builtin in ('cd', 'pushd', 'popd', 'export', 'unset') + _TRANSFER_SETS + _TRANSFER_DECLARES or assigns:
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
        # A new shell starts with its own options, not the outer shell's: -e, -a and -n, or their -o names.
        options = _transfer_shell_flags(args)[2] if program in _TRANSFER_SHELLS else {}
        nested = {k: v for k, v in env.items() if k not in _TRANSFER_SET_OPTIONS.values()}
        nested.update((_TRANSFER_SET_OPTIONS[name], value) for name, value in options.items() if name != 'noexec')
        calls = [] if options.get('noexec') == '1' else _transfer_walk(items, cwd, nested, depth + 1, positional)
        if options.get('noexec'):
            _transfer_unsure_calls(calls)  # zsh's spelling of -n, which bash rejects: it may not run them
        calls = [call[:4] + (call[4] or other_user, call[5] + (layer,)) + call[6:] for call in calls]
    else:
        calls = [(program, args, env, cwd, other_user, (layer,), False)] if program else []
    if program:
        _transfer_replace(words, subshell, shell)
    if known:
        _transfer_unsure_calls(calls)  # a function of the same name, which may have been defined, may run instead
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
    if words:
        _transfer_errexit(after, shell)
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


def _transfer_ends_list(head: tuple, shell: Dict) -> bool:
    """Whether the compound opening at head, in the item being read, is followed by && or ||."""
    item = shell['items'][shell['at']] if shell['at'] < len(shell['items']) else head
    k = len(item[1]) - len(head[1]) if head[0] == 'cmd' and item[0] == 'cmd' else 0
    return shell['ends'].get((shell['at'], k), ('', None))[0] in ('&&', '||')


def _transfer_exempt(shell: Dict) -> bool:
    """Whether set -e is ignored here: in a condition, or in a compound or function body run in an && or || list but
    as its last command, or behind a !."""
    return bool(shell.get('exempt')) or any(f['exempt'] or f['cond'] for f in shell['frames'])


def _transfer_errexit(after: str, shell: Dict) -> None:
    """Under set -e, a command that surely fails where it is not ignored ends the shell or subshell; one whose status
    isn't known goes on. bash ignores set -e in a command substitution and zsh does not, so there it only may end it."""
    errexit = shell['vars'].get(_TRANSFER_ERREXIT, ('', True))[0]
    if not errexit or after in ('&&', '||', '|') or shell['status'] in (0, None) or shell['pipe']['runs'] is False or \
            shell['pipe']['negate'] or _transfer_exempt(shell):
        return
    outside = _transfer_liveness(shell)
    _transfer_jump('exit', [], shell)
    if errexit != '1' or any(f['kind'] == '$(' for f in shell['frames']):
        _transfer_soften(outside, shell)


def _transfer_ends_piped(head: tuple, shell: Dict) -> bool:
    """Whether the compound opening at head, in the item being read, is piped or backgrounded at its end."""
    item = shell['items'][shell['at']] if shell['at'] < len(shell['items']) else head
    k = len(item[1]) - len(head[1]) if head[0] == 'cmd' and item[0] == 'cmd' else 0
    return shell['ends'].get((shell['at'], k), ('', None))[0] in ('|', '&')


def _transfer_walk(items: List[tuple], cwd: Optional[str], exported: Dict, depth: int,
                   positional: List[str] = ()) -> List[tuple]:
    """Each simple command that runs or may run, as (program, args, env, folder, other_user, layers, unsure);
    skipped branches and uncalled function bodies are left out."""
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
    """Whether a proxy resolves a curl URL's name: HTTP, SOCKS4A and socks5h do, SOCKS4 and SOCKS5 resolve here,
    and an empty -x or a --noproxy (else no_proxy) entry turns it off. kind None is curl's environment proxy."""
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


def _transfer_curl(args: List[str], env: Optional[Dict] = None, state: Optional[Dict] = None) -> List[tuple]:
    """curl's URLs, sent to when their request uploads or sends data, else fetched from, each with whether a proxy
    resolves its name (it then gets the --connect-to target and no --resolve pin); pins carry past --next."""
    # Unless its first argument is -q or --disable, curl first reads its default config; one with any option beyond the
    # safe ones may change where it connects, what it sends or which URLs it fetches, so nothing is claimed for it.
    skips = bool(args) and (args[0].startswith('-q') or args[0] == '--disable')
    if not skips and state is not None and _transfer_curlrc_unsafe(env or {}, state):
        return []
    endpoints, pins, configured, i = [], [], False, 0
    while True:
        urls, (sends, uploads, local, config, resolver), overrides, globoff, i, (kind, noproxy), scheme = \
            _transfer_curl_request(args, i)
        # A -K config this doesn't read may reroute this request and those after it, a literal address included.
        configured = configured or config
        if urls is None:
            return []  # curl reads every option before it sends anything
        pins += [value for option, value in overrides if option == '--resolve']
        connects = [value for option, value in overrides if option == '--connect-to']
        # Through --unix-socket or --abstract-unix-socket, the request reaches a local socket, not the URL's host.
        for index, url in enumerate([] if local else urls):
            # The Nth -T uploads to the Nth URL; a URL past them is fetched unless the request sends a body.
            out = sends or index < uploads
            # A URL with no scheme takes --proto-default's, and so that scheme's port.
            url = scheme + '://' + url.strip() if scheme and not re.match(r'\s*[A-Za-z][A-Za-z0-9+.-]*://', url) else url
            expanded = [url] if globoff else _transfer_curl_glob(url)
            if expanded is None:
                return endpoints
            for one in expanded:
                remote = _transfer_curl_remote(one, kind, noproxy, env or {})
                # With its own resolver a name isn't looked up here; a pin or a literal address still holds.
                endpoints.append(('out' if out else 'in', _transfer_url_host(one, _TRANSFER_CURL_SCHEMES), None,
                                  _transfer_curl_dial(one, connects, [] if remote else pins),
                                  'rerouted' if configured else remote or resolver))
        if i >= len(args):
            return endpoints


# Default-config options that can't change where curl connects, what it sends or which URLs it fetches, and their
# short forms; a config with any other may change any of that.
_TRANSFER_CURLRC_SAFE = frozenset((
    'user-agent silent show-error verbose progress-bar progress-meter no-progress-meter connect-timeout max-time retry '
    'retry-delay retry-max-time retry-connrefused retry-all-errors compressed fail fail-with-body include show-headers '
    'write-out create-dirs remote-time limit-rate keepalive keepalive-time no-keepalive tcp-nodelay http1.1 http2 '
    'speed-limit speed-time expect100-timeout').split())
_TRANSFER_CURLRC_SAFE_SHORT = frozenset('AsSv#mfiwRYy')
# Command-line options that send curl's own name lookups to another resolver.
_TRANSFER_CURL_RESOLVERS = frozenset({'--doh-url', '--dns-servers', '--dns-interface', '--dns-ipv4-addr',
                                     '--dns-ipv6-addr'})


def _transfer_curlrc(env: Dict) -> Optional[str]:
    """The default config curl 8.5 reads, found as it finds one: .curlrc in $CURL_HOME, $XDG_CONFIG_HOME or $HOME, on
    Windows also %USERPROFILE% and %APPDATA% and as _curlrc, then curlrc in .config, then the account's home; None for
    none, and '' when where it is isn't known."""
    def setting(key: str) -> Optional[str]:
        return env[key] if key in env else None if _TRANSFER_CLEAN_ENV in env else os.environ.get(key)
    places = [('CURL_HOME', '', False), ('XDG_CONFIG_HOME', '', False), ('HOME', '', False)]
    if _TRANSFER_WINDOWS:
        places += [('USERPROFILE', '', False), ('APPDATA', '', False), ('USERPROFILE', '\\Application Data', False)]
    places += [('CURL_HOME', '/.config', True), ('HOME', '/.config', True)]
    xdg = False
    for key, append, plain in places:
        value = setting(key)
        xdg = xdg or (key == 'XDG_CONFIG_HOME' and value is not None)
        if not value or (plain and xdg):
            continue
        if _TRANSFER_SUBSTITUTED in value:
            return ''
        for name in ['curlrc'] if plain else ['.curlrc', '_curlrc'] if _TRANSFER_WINDOWS else ['.curlrc']:
            if os.path.isfile(os.path.join(value + append, name)):
                return os.path.join(value + append, name)
    home = _transfer_home()
    return os.path.join(home, '.curlrc') if home and os.path.isfile(os.path.join(home, '.curlrc')) else None


def _transfer_curlrc_unsafe(env: Dict, state: Dict) -> bool:
    """Whether curl's default config names an option outside the safe ones, read once a turn by option names alone,
    never their values; true when where it is isn't known or it can't be read."""
    path = _transfer_curlrc(env)
    if path is None:
        return False
    if ('curlrc', path) not in state:
        state[('curlrc', path)] = not path or _transfer_curlrc_has_unsafe(path)
    return state[('curlrc', path)]


def _transfer_curlrc_has_unsafe(path: str) -> bool:
    """Whether a curl config names an option outside the safe ones, as curl reads one: an option per line, -x or --name
    or name before a space, = or :, # and blank lines skipped; true when it can't be read."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read(_TRANSFER_SSH_CONFIG_MAX_BYTES + 1)
    except OSError:
        return True
    if len(data) > _TRANSFER_SSH_CONFIG_MAX_BYTES:
        return True
    for line in data.decode('utf-8', 'replace').split('\n'):
        line = line.lstrip()
        if not line or line[0] in '#/\r*':
            continue
        name = re.match(r'[^\s]*' if line[0] == '-' else r'[^\s=:]*', line).group()
        if line[0] == '-' and not name.startswith('--'):
            # A cluster's letters up to the one that takes a value, whose value the rest is.
            for flag in name[1:]:
                if flag not in _TRANSFER_CURLRC_SAFE_SHORT:
                    return True
                if flag in _TRANSFER_CURL_SHORT_VALUES:
                    break
            continue
        option = _transfer_curl_long('--' + name[2:] if name.startswith('--') else '--' + name)[2:]
        if (option[3:] if option.startswith('no-') else option) not in _TRANSFER_CURLRC_SAFE:
            return True
    return False


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
    return (_transfer_ip_text(addresses[0]) if addresses else target[0]), addresses


def _transfer_prefixed(name: str, options: frozenset) -> str:
    """A long option as getopt and curl up to 8.5 read it: the exact name, else the one option it starts; '' when it
    starts several, which the tool rejects, and the name as written when it starts none."""
    word = name[2:]
    hits = [word] if not word or word in options else [option for option in options if option.startswith(word)]
    return '--' + hits[0] if len(hits) == 1 else '' if hits else name


def _transfer_curl_long(name: str) -> str:
    """A curl long option, read ignoring case as curl up to 8.5 does; a --no- or --expand- form must be exact."""
    word = name[2:].lower()
    if not word or word.startswith(('no-', 'expand-')):
        return '--' + word if word else name
    return _transfer_prefixed('--' + word, _TRANSFER_CURL_LONG_OPTIONS)


# Options that make curl print help, its manual or its version and exit before any transfer.
_TRANSFER_CURL_INFO = frozenset({'-h', '--help', '-M', '--manual', '-V', '--version'})
# Options whose value picks where a request goes, besides the proxies; a variable expanded into one leaves that unknown.
_TRANSFER_CURL_ROUTES = frozenset({'--url', '--resolve', '--connect-to', '--preproxy', '--noproxy', '--proto-default',
                                   '--unix-socket', '--abstract-unix-socket'})


def _transfer_curl_request(args: List[str], i: int) -> tuple:
    """The curl request at args[i]: URLs (None when rejected), (sends body, -T count, local socket, -K or an expanded
    route, own resolver),
    --resolve and --connect-to, globoff, next start, (proxy kind: '' off, None unnamed; --noproxy), --proto-default."""
    urls, flags, method, overrides, scheme, uploads, local = [], set(), '', [], '', 0, False
    kind, preproxy, noproxy, routed = None, None, None, False
    while i < len(args):
        arg, value, expand, i = args[i], None, False, i + 1
        if arg == '--':
            urls, i = urls + args[i:], len(args)  # every word after it is a URL, a --next too
            break
        if arg.startswith('--'):
            # curl reads --name=value as --name value, and --expand-name as --name with variables expanded.
            arg, eq, attached = arg.partition('=')
            arg = _transfer_curl_long(arg)
            if not arg:
                return None, (False, 0, False, False, False), [], False, len(args), (None, None), ''  # rejected
            if arg == '--next':
                break
            expand = arg.startswith('--expand-')
            arg = '--' + arg[len('--expand-'):] if expand else arg
            if eq:
                value = attached
            elif arg in _TRANSFER_CURL_LONG_VALUES and i < len(args):
                value, i = args[i], i + 1
        elif arg == '-:':
            break
        elif arg.startswith('-') and len(arg) > 1:
            arg, value, i = _transfer_short_option(arg, args, i, _TRANSFER_CURL_SHORT_VALUES, flags)
        else:
            urls.append(arg)
            continue
        flags.add(arg)
        flags -= _TRANSFER_CURL_UNDOES.get(arg, set())
        if flags & _TRANSFER_CURL_INFO:
            return None, (False, 0, False, False, False), [], False, len(args), (None, None), ''  # it only prints
        routed = routed or bool(expand and value and '{{' in value and
                                (arg in _TRANSFER_CURL_ROUTES or arg in _TRANSFER_CURL_PROXIES))
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
        elif arg in ('-T', '--upload-file') and value is not None:
            uploads += 1
        elif arg in ('--unix-socket', '--abstract-unix-socket') and value is not None:
            local = True
    sends = flags & _TRANSFER_CURL_UPLOADS or method in _TRANSFER_SENDING_METHODS or \
        (flags & _TRANSFER_CURL_BODIES and not flags & {'-G', '--get'})
    # Without -x, a --preproxy is the SOCKS proxy the request goes through.
    marks = (bool(sends), uploads, local, bool(flags & {'-K', '--config'}) or routed,
             bool(flags & _TRANSFER_CURL_RESOLVERS))
    return urls, marks, overrides, bool(flags & {'-g', '--globoff'}), i, \
        (kind if kind is not None else preproxy, noproxy), scheme


def _transfer_wget(args: List[str], proxied: bool = False) -> List[tuple]:
    """wget's URLs: sent to when it posts data or a file; else fetched from. Each carries whether it goes through a
    proxy: one the command set or an -e proxy setting, unless --no-proxy or -e use_proxy=off turns proxies off."""
    urls, flags, settings, method, i = [], set(), {}, '', 0
    while i < len(args):
        arg, name, value, i = args[i], None, None, i + 1
        if arg == '--':
            urls.extend(args[i:])  # every word after it is a URL
            break
        if arg.startswith('--'):
            name, eq, value = arg.partition('=')
            name = _transfer_prefixed(name, _TRANSFER_WGET_LONG_OPTIONS)
            if not name:
                return []  # wget rejects an option that starts several, and fetches nothing
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
            settings[key.replace('_', '').replace('-', '')] = setting
            method = setting.upper() if key.replace('_', '').replace('-', '') == 'method' else method
        elif name == '--method' and value:
            method = value.strip().upper()
    if flags & {'-h', '--help', '-V', '--version'}:
        return []  # it prints and exits before fetching anything
    if '--config' in flags:
        return []  # a config this doesn't read may change what it sends and where
    on = settings.get('useproxy', 'on') in ('on', 'yes', '1') and '--no-proxy' not in flags
    proxy = on and (proxied or any(settings.get(k) for k in ('httpproxy', 'httpsproxy', 'ftpproxy')))
    # An -e post_data, post_file, body_data or body_file setting sends as its option does.
    sends = flags & _TRANSFER_WGET_UPLOADS or method in _TRANSFER_SENDING_METHODS or \
        any(settings.get(k) for k in ('postdata', 'postfile', 'bodydata', 'bodyfile'))
    return [('out' if sends else 'in', _transfer_url_host(url, _TRANSFER_WGET_SCHEMES), None, None, proxy)
            for url in urls]


def _transfer_ssh_args(program: str, args: List[str], switches: Optional[set] = None) -> tuple:
    """(operands, the options that change which host or user ssh -G resolves) for ssh, scp or sftp; switches,
    if given, collects flags such as -n and the first -o StdinNull as yes, no or bad (a value ssh rejects)."""
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
        if flag in ('-Q', '-O'):
            switches.add(flag + '=' + (value or '').strip().lower())  # ssh's query, or its master-control command
        if flag == '-S' and program != 'ssh' and _transfer_program_name(value or '') != 'ssh':
            passthrough += list(_TRANSFER_CONFIG_UNKNOWN)  # scp's or sftp's own program may connect anywhere
    return operands, passthrough


def _transfer_rsync_args(args: List[str], env: Dict) -> tuple:
    """(operands, ssh options for its remote shell, an unknown config when that shell isn't ssh, whether -e or --rsh
    named it) for rsync."""
    shell, operands, explicit, i = _transfer_env(env, 'RSYNC_RSH'), [], False, 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == '--':
            operands.extend(args[i:])  # every word after it is an operand
            break
        if arg == '--rsh' and i < len(args):
            shell, explicit, i = args[i], True, i + 1
        elif arg.startswith('--rsh='):
            shell, explicit = arg.split('=', 1)[1], True
        elif arg in _TRANSFER_RSYNC_VALUE_OPTIONS:
            i += 1
        elif arg.startswith('-') and not arg.startswith('--'):
            flag, value, i = _transfer_short_option(arg, args, i, _TRANSFER_SSH_VALUE_FLAGS['rsync'], set())
            shell, explicit = (value, True) if flag == '-e' else (shell, explicit)
        elif not arg.startswith('-'):
            operands.append(arg)
    if not shell:
        return operands, [], False
    words = _transfer_words(shell)
    if not words or _transfer_program_name(words[0]) != 'ssh':
        return operands, list(_TRANSFER_CONFIG_UNKNOWN), explicit  # a remote shell of its own may connect anywhere
    return operands, _transfer_ssh_args('ssh', words[1:] + ['-'])[1], explicit


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
    # On Windows one letter before the colon is a drive, a local path, with or without a slash after; elsewhere scp
    # dials host C.
    if not match or (_TRANSFER_WINDOWS and re.match(r'^[A-Za-z]:', arg)):
        return None
    return match.group(1), None, not match.group(2)


def _transfer_copy(program: str, args: List[str], env: Dict) -> List[tuple]:
    """Each remote side of an scp, sftp or rsync copy: fetched from as a source, sent to as the target."""
    operands, options, explicit = _transfer_rsync_args(args, env) if program == 'rsync' else \
        _transfer_ssh_args(program, args) + (False,)
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
            # With -e or --rsh, though not RSYNC_RSH alone, rsync reaches a daemon through that shell, on no TCP port.
            via_ssh, port = (True, None) if explicit and not via_ssh else (via_ssh, port)
            ssh_options = (options + (['-p', port] if port else [])) if via_ssh and options is not None else None
            endpoints.append((direction, destination, ssh_options))
    return endpoints


def _transfer_ssh_pipe(args: List[str], sends: bool, receives: bool) -> List[tuple]:
    """ssh used as a pipe: sent to when its stdin is fed in, fetched from when its stdout is kept. -n, -f, which implies
    it, and a first -o StdinNull=yes keep stdin unread; ForkAfterAuthentication=yes still sends it."""
    switches = set()
    operands, options = _transfer_ssh_args('ssh', args, switches)
    # -G, -V and -Q only print, and -O check, exit, stop, forward or cancel only controls a master connection.
    controls = {'-O=' + command for command in ('check', 'exit', 'stop', 'forward', 'cancel')}
    if not operands or 'StdinNull=bad' in switches or switches & ({'-G', '-V'} | controls) or \
            any(switch.startswith('-Q=') for switch in switches):
        return []
    sends = sends and not switches & {'-n', '-f', 'StdinNull=yes'}
    return [(d, operands[0], options) for d, used in (('out', sends), ('in', receives)) if used]


def _transfer_netcat(args: List[str], sends: bool, ncat: bool = False) -> List[tuple]:
    """nc's host, sent to when stdin is fed in; ncat --proxy or nc -x resolve it remotely unless ncat --proxy-dns
    local/both or nc -X 4 resolves it here; a listener reaches no host and -X without -x connects directly."""
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
            # ncat's -c runs a command, while OpenBSD and macOS nc's -c is a switch.
            values_flags = _TRANSFER_NC_SHORT_VALUES | ({'c'} if ncat else set())
            flag, value, i = _transfer_short_option(arg, args, i, values_flags, flags)
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
    """The web cmdlet parameter a -Name binds to, as PowerShell resolves it: exact name or alias, else the one
    it prefixes, cmdlet's own first; empty when ambiguous and the name itself when it prefixes none."""
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
    uri, out, positional, proxy, named, i = '', sends, [], None, set(), 0
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
        if (colon and not value or not colon and name not in _TRANSFER_PS_SWITCHES) and i < len(args):
            value, i = args[i], i + 1  # -Name: value binds the next word, even for a switch
        if name == 'uri':
            uri = value
        elif name in ('body', 'infile', 'form'):
            out = True
        elif name in ('method', 'custommethod') and value.upper() in _TRANSFER_SENDING_METHODS:
            out = True
        elif name == 'unixsocket' and value:
            return []  # it reaches a local socket, not the URI's host
        elif name == 'proxy':
            proxy = bool(value)
            named |= {name} if value else set()
        elif name == 'noproxy':
            named.add(name)
            # -NoProxy:$false, or a value not known here, leaves the proxy on.
            proxy = False if not colon or value.lower() in ('$true', '1') else proxy
    if named == {'proxy', 'noproxy'}:
        return []  # -Proxy and -NoProxy, whatever its value, are in different parameter sets: PowerShell rejects them
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


def _transfer_parse(program: str, args: List[str], env: Dict, other_user: bool, layers: tuple,
                    state: Optional[Dict] = None) -> Optional[tuple]:
    """(tool, [(direction, destination, ssh -G options or None[, curl's dial])]) for a transfer command; None for any
    other."""
    tool, (sends, keeps) = _TRANSFER_TOOLS.get(program), _transfer_stdio(layers)
    if tool in ('scp', 'sftp', 'rsync'):
        raw = _transfer_copy(tool, args, env)
    elif tool == 'ssh':
        raw = _transfer_ssh_pipe(args, sends, keeps)
    elif tool in ('curl', 'wget'):
        args = _transfer_stdin_args(tool, args, _transfer_stdin_text(layers))
        raw = _transfer_curl(args, env, state) if tool == 'curl' else _transfer_wget(args, _transfer_proxied(env))
    elif tool in ('nc', 'socat'):
        raw = _transfer_netcat(args, sends, program == 'ncat') if tool == 'nc' else _transfer_socat(args, sends)
    elif tool in ('httpie', 'powershell'):
        raw = (_transfer_httpie if tool == 'httpie' else _transfer_web_cmdlet)(args, sends, _transfer_proxied(env))
    else:
        return None
    # Under sudo, ssh reads that user's config, which isn't known here, so the host is never looked up.
    unknown = list(_TRANSFER_CONFIG_UNKNOWN) if other_user else []
    return tool, [(e[0], e[1], None if e[2] is None else list(e[2]) + unknown) + e[3:] for e in raw]


def _transfer_clean_host(host: str) -> str:
    """A host name or address in lower case without brackets; empty when it isn't one."""
    import ipaddress
    host = host.strip().lower()
    host = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    if re.match(r'^[a-z0-9_][a-z0-9_.-]{0,252}$', host):
        return host
    try:
        return _transfer_ip_text(ipaddress.ip_address(host.split('%')[0])) if ':' in host else ''
    except ValueError:
        return ''


def _transfer_ip_text(address) -> str:
    """An address as the hooks print it: compressed, and an IPv4-mapped one as ::ffff:a.b.c.d, which Python versions
    otherwise print differently."""
    mapped = getattr(address, 'ipv4_mapped', None)
    return '::ffff:' + str(mapped) if mapped else str(address)


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
    """One ssh config line read as ssh reads it: (whether it is an Include, the files it names, resolved against the
    home and folder ssh uses); None when it could run a command or a DNS lookup, or ssh may read it differently."""
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
    home, env_home = _transfer_home(), os.path.expanduser('~')
    # ssh reads ~/.ssh/config from the account's home, but globs an Include's ~ and relative path, and glob expands ~
    # with $HOME. Windows' ssh may read it otherwise, so there the two must agree.
    if _TRANSFER_WINDOWS and env_home != home:
        return None
    homes = [env_home]
    user_bases = (os.path.join(env_home, '.ssh'),)
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


# The user's and the system's ssh configs, as a command names them.
_TRANSFER_SSH_CONFIG_NAMES = re.compile(r'\.ssh(?:/|\\+)config\b|ssh_config\b', re.IGNORECASE)


def _transfer_turn_text(inputs) -> str:
    """Every tool call's input in a turn as one text, to tell whether any names an ssh config. Never raises."""
    import json
    parts = []
    for item in inputs:
        try:
            parts.append(item if isinstance(item, str) else json.dumps(item, default=str))
        except Exception:
            pass
    return '\n'.join(parts)


def _transfer_ssh_config_named(options: List[str], state: Dict) -> bool:
    """Whether a call in the turn names an ssh config this lookup reads (user, system, or a -F file other than
    as -F); rewriting one can move an earlier transfer, as ssh -G reads configs only at turn end."""
    text = state.get('turn_text', '') + '\n' + state.get('call_text', '')
    if _TRANSFER_SSH_CONFIG_NAMES.search(text):
        return True
    names = {os.path.basename(v) for i, v in enumerate(options) if i and options[i - 1] == '-F' and v != 'none'}
    text = re.sub(r'-F\s*\S+', ' ', text)
    return any(name and re.search(r'(?<![\w.-])' + re.escape(name) + r'(?![\w.-])', text, re.IGNORECASE)
               for name in names)


def _transfer_ssh_hostname(destination: str, options: List[str], cwd: Optional[str], state: Dict) -> tuple:
    """(the host ssh connects to for a destination, read from ssh -G, empty when it can't be looked up safely, whether
    ssh -G reports a jump host or proxy command for it)."""
    configs = [v for i, v in enumerate(options) if i and options[i - 1] == '-F']
    if any(v.startswith(('~', _TRANSFER_SUBSTITUTED)) for v in configs):
        return '', False  # a HOME not known, or a ~ the shell left, which ssh reads as it is, as in rsync -e
    if _transfer_ssh_config_named(options, state):
        return '', True  # a config it reads may have changed since the transfer, so neither ssh -G nor DNS runs
    key = ('ssh', destination, tuple(options), cwd)
    if key not in state:
        state[key] = '', False
        # A destination starting with - would reach ssh -G as an option.
        if not destination.startswith('-'):
            target = destination.replace('[', '').replace(']', '')
            out = _transfer_run(['ssh', '-G'] + options + ['--', target], cwd, state) or ''
            names = [line.split(None, 1)[1] for line in out.splitlines() if line.startswith('hostname ')]
            # Some ssh versions print `proxyjump none` and `proxycommand none` for a host with neither.
            jumps = any(line.split(None, 1)[0] in ('proxyjump', 'proxycommand') and line.split(None, 1)[1:] != ['none']
                        for line in out.lower().splitlines() if line.strip())
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
    """One place a transfer reached: host as written without login, the host it connects to (ssh -G or curl's dial) and
    its address kind. Without lookup only a literal dialled address is classified; an ssh, proxy or jump host's target never is."""
    direction, destination, ssh_options = raw[:3]
    dial = raw[3] if len(raw) > 3 else None
    lookup = lookup and not (len(raw) > 4 and raw[4])
    destination = destination.strip()
    host = _transfer_url_host(destination, _TRANSFER_CURL_SCHEMES) if '://' in destination else \
        destination.rsplit('@', 1)[-1]
    host = _transfer_clean_host(host)
    if not host:
        return None
    if len(raw) > 4 and raw[4] == 'rerouted':
        resolved, address = host, 'unresolved'  # a config this didn't read may send it anywhere
    elif dial:
        resolved = dial[0]
        address = _transfer_address_kind(dial[1]) if dial[1] else _transfer_address(dial[0], state, lookup)
    else:
        lookup = lookup and not (ssh_options is not None and _transfer_ssh_jumps(ssh_options))
        resolved, jumps = _transfer_ssh_hostname(destination, ssh_options, cwd, state) if ssh_options is not None and \
            lookup else ('', False)
        # Without a successful ssh -G a config or -o HostName may send even a literal address elsewhere, so nothing is
        # classified.
        failed = ssh_options is not None and not (lookup and resolved)
        # Through a jump host or proxy command the bytes go where it sends them, not to the config's HostName.
        resolved = host if jumps or failed else resolved or host
        address = 'unresolved' if failed or jumps else _transfer_address(resolved, state, lookup)
    endpoint = {'direction': direction, 'host': host, 'resolved_host': resolved, 'address': address}
    return {k: v for k, v in endpoint.items() if v}


def _transfer(command: Optional[str], cwd: Optional[str], state: Dict, sure: bool = True) -> Optional[Dict]:
    """Where a shell call's transfers went: the first transfer tool it ran and each place it sent to or fetched
    from, looked up only when the call surely ran; None when it ran no transfer. Never raises or outlasts the budget."""
    try:
        if not isinstance(command, str) or not command.strip():
            return None
        tool, endpoints, state['call_text'] = None, [], command
        for program, args, env, call_cwd, other_user, layers, unsure in \
                _transfer_walk(_TransferLexer(command).read() or [], cwd, {}, 0):
            found = _transfer_parse(program, args, env, other_user, layers, state)
            for raw in (found[1] if found else []):
                if len(endpoints) >= _TRANSFER_MAX_ENDPOINTS:
                    break
                endpoint = _transfer_endpoint(raw, call_cwd, state, sure and not unsure)
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


# How Codex reports an exec_command that never ran: blocked by a hook, rejected by the user, or denied by the sandbox.
_CODEX_NOT_RUN_OUTPUTS = ('Command blocked by PreToolUse hook', 'Tool call blocked by PreToolUse hook',
                          'exec command rejected by user', 'rejected by user', 'Command denied by sandbox')


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
                                'arguments': arguments,
                                'timestamp': entry_timestamp
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
        # Every call's input, so a turn that names an ssh config makes no ssh lookups.
        transfer_state: Dict = {'turn_text': _transfer_turn_text(c.get('arguments') for c in function_calls.values())}
        for call_id, call_data in function_calls.items():
            name = call_data.get('name', '')
            args = call_data.get('arguments', {})
            output = function_outputs.get(call_id, '')

            # Map Codex function names to tool names
            # Codex currently only has exec_command (Bash). Other function names
            # are handled generically as fallback for future Codex tool support.
            transfer = None
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
                # Each exec_command starts a new shell in its workdir or the session folder, so no cd carries over.
                start = os.path.join(session_cwd or '', workdir) if isinstance(workdir, str) and workdir else session_cwd
                start = start if start and os.path.isabs(start) else None
                # A call with no output, or one blocked or rejected before it ran, is not looked up.
                ran = call_id in function_outputs and not str(output).startswith(_CODEX_NOT_RUN_OUTPUTS)
                transfer = _transfer(command, start, transfer_state) if ran else None
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

            tool_use = _with_call_ts({
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response,
                'tool_use_id': call_id,
                'project': project
            }, call_data.get('timestamp'))
            if transfer:
                tool_use['transfer'] = transfer
            tool_uses.append(tool_use)

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
        'project': _get_project(cwd),
        'account_identity': build_account_identity(probe=True),
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
            api_key = _machine_env('UNBOUND_CODEX_API_KEY')
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
                api_key = _machine_env('UNBOUND_CODEX_API_KEY')
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


def get_api_key():
    return os.getenv('UNBOUND_CODEX_API_KEY')


def main():
    global _cached_api_key
    api_key = os.getenv('UNBOUND_CODEX_API_KEY')
    _cached_api_key = api_key

    if len(sys.argv) > 1 and sys.argv[1] == '--sync-skills':
        _sync_skills_once(api_key)
        return

    try:
        input_data = sys.stdin.read().strip()

        if not input_data:
            _emit('{}')
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            _emit('{}')
            return

        hook_event_name = event.get('hook_event_name')

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "SessionStart":
            _cleanup_skill_policy_state()
            _dispatch_discovery()
            _dispatch_skills_sync(api_key)
            _emit("{}")
            return
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            _emit(json.dumps(response))
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
                _emit(json.dumps(response))
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
                _emit(json.dumps(response))
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
        _emit('{}')

    except Exception as e:
        # Still acknowledge so Codex sees the hook complete.
        log_error(f"Exception in main: {str(e)}", 'general')
        _emit('{}')


if __name__ == '__main__':
    main()
