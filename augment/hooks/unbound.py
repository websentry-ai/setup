#!/usr/bin/env python3

import sys
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
# Non-MCP Augment tools we always evaluate (the rest fall through to the cache
# fast path). MCP tools are detected via the is_mcp_tool flag, not a name prefix.
ALLOWED_NON_MCP_HOOK_NAMES = ['launch-process', 'str-replace-editor', 'save-file', 'view', 'read-file', 'remove-files']
CLAUDE_PLUGIN_CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
POLICY_CACHE_FILE = Path.home() / ".augment" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
AUDIT_LOG_TOTAL_LIMIT = 100

APPROVAL_TIMEOUT = 4 * 60 * 60

# Per-attempt curl timeout (seconds) for the PreToolUse policy-check path
# (send_to_hook_api). The installed PreToolUse hook timeout is 15000ms (see
# build_hooks_block in setup.py / mdm/setup.py), so the WORST-CASE network
# budget for this path must stay comfortably under 15s or Augment kills the
# hook mid-request instead of letting it fail open. Budget: 3 attempts x 4s
# curl + 2 x 0.5s backoff = ~13s worst case < 15s. Keep a retry for transient
# blips. Only this pretool path uses the reduced timeout — the approval-poll
# and audit/error curls are unchanged.
PRETOOL_CURL_TIMEOUT = 4

DISCOVERY_DEBOUNCE_SECONDS = 24 * 3600
DISCOVERY_HOOK_FLAG_TTL_SECONDS = 24 * 3600
DISCOVERY_HOOK_FLAG_PATH = "/v1/hooks/discovery-enabled"
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


def log_error(message: str, category: str = 'general'):
    """Log error with timestamp to error.log, keeping only last 25 errors."""
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
            'last_synced': _utc_now_z(),
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
        }
        with open(POLICY_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cache))
    except (OSError, TypeError):
        pass


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

    # File families (edit/write/read/delete): the path.
    if family in ('Edit', 'Write', 'Read', 'Delete') or tool_name in NATIVE_FILE_TOOLS:
        for key in ('path', 'file_path', 'filePath'):
            value = tool_input.get(key)
            if value:
                return value if isinstance(value, str) else json.dumps(value)
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

    for attempt in range(3):
        try:
            # Auth header off-argv (0600 temp file); body off-argv (stdin).
            result = curl_with_auth(
                [f"Authorization: Bearer {api_key}"],
                ["-fsSL", "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data.encode(),
                # Reduced from 20s so 3 attempts x PRETOOL_CURL_TIMEOUT + backoffs
                # stays under the 15000ms PreToolUse hook timeout (see constant).
                timeout=PRETOOL_CURL_TIMEOUT,
            )
            if result is None:
                return {}

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

    Auggie 0.30.0 does NOT deliver context.userEmail (the includeUserContext
    metadata flag that would gate it is intentionally not seeded — see setup.py),
    so the event's injected context is absent on every real event today. We still
    read context.userEmail when present for forward-compat with a future Auggie
    that delivers it; otherwise we fall back to the `email` field the installer
    writes into ~/.unbound/config.json. There is no on-disk account record beyond
    that, so org/plan/auth_mode are always None (the gateway resolves the org from
    the API key). Fully fail-safe: any read error -> None, never raises."""
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


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """Process PreToolUse event - DO NOT LOG."""
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
        # Augment injects mcp_metadata (when includeMCPMetadata is set on the
        # matcher); read the executed server/tool for gateway matching.
        mcp_metadata = event.get('mcp_metadata')
        if isinstance(mcp_metadata, dict):
            mcp_server_name = (mcp_metadata.get('mcpExecutedToolServerName') or '').strip()
            metadata['mcp_server'] = mcp_server_name
            metadata['mcp_tool'] = (mcp_metadata.get('mcpExecutedToolName') or '').strip()
            if mcp_server_name:
                plugin_cfg = _resolve_plugin_mcp_config(mcp_server_name)
                if plugin_cfg:
                    metadata['mcp_server_config'] = plugin_cfg

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

    _tuid = event.get('tool_use_id')
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


def _augment_posttooluse_to_exchange(ev: Dict) -> Optional[Dict]:
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
        server = (mcp.get('mcpExecutedToolServerName') or '').strip() or 'unknown'
        tool = (mcp.get('mcpExecutedToolName') or '').strip() or raw_name or 'unknown'
        return {
            'type': 'PostToolUse',
            'tool_name': f'mcp__{server}__{tool}',
            'tool_input': tool_input,
            'tool_response': _io_response(),
            'tool_use_id': ev.get('tool_use_id'),
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
        'tool_use_id': ev.get('tool_use_id'),
    }


def build_llm_exchange(event: Dict, post_tool_events: List[Dict], model: Optional[str] = None) -> Optional[Dict]:
    """Build the end-of-turn exchange for the audit endpoint from Augment's Stop
    event. With includeConversationData set, Augment injects the turn under
    event._exchange.exchange.{request_message, response_text}; the PostToolUse
    tool calls are reconstructed from the accumulated audit log."""
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

    for log_entry in post_tool_events:
        ev = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        if ev.get('hook_event_name') != 'PostToolUse':
            continue
        shaped = _augment_posttooluse_to_exchange(ev)
        if shaped:
            assistant_tool_uses.append(shaped)

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
        # (e.g. Stop omitted conversation.userPrompt, so messages < 2). Do NOT
        # drop it silently — emit a visible local log line and a best-effort,
        # fire-and-forget gateway report (fail-open: never raises, never blocks).
        log_error(
            f"Dropped Stop turn for session={session_id}: "
            f"{len(session_events)} PostToolUse record(s) but no usable exchange "
            f"(missing userPrompt/assistant content)",
            'dropped_turn',
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


def _hook_discovery_enabled_for_org() -> bool:
    """Return whether SessionStart-triggered discovery is enabled for this
    user's org. Reads ~/.unbound/discovery-cache.json first; refetches from
    the gateway only when the cached value is missing or older than
    DISCOVERY_HOOK_FLAG_TTL_SECONDS. Fail-closed: any error and no usable
    cached value means False."""
    cache: Dict = {}
    if DISCOVERY_CACHE_PATH.exists():
        try:
            with DISCOVERY_CACHE_PATH.open("r", encoding="utf-8") as f:
                cache = json.load(f) or {}
        except (OSError, json.JSONDecodeError):
            cache = {}
    if not isinstance(cache, dict):
        cache = {}
    _hd = cache.get("hook_discovery")
    flag = _hd if isinstance(_hd, dict) else {}
    last_fetched = flag.get("fetched_at")
    if isinstance(last_fetched, str):
        try:
            ts = datetime.strptime(last_fetched, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if (time.time() - ts) < DISCOVERY_HOOK_FLAG_TTL_SECONDS:
                return bool(flag.get("enabled", False))
        except ValueError:
            pass

    try:
        with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
            cfg = json.load(f) or {}
    except (OSError, json.JSONDecodeError):
        return bool(flag.get("enabled", False))
    api_key = cfg.get("api_key")
    if not api_key:
        return bool(flag.get("enabled", False))
    url = f"{UNBOUND_GATEWAY_URL}{DISCOVERY_HOOK_FLAG_PATH}"
    try:
        # Auth header off-argv (0600 temp file) — GET, no body.
        r = curl_with_auth(
            [f"Authorization: Bearer {api_key}"],
            ["-fsSL", "--max-time", "5", url],
            timeout=8,
        )
        if r is None or r.returncode != 0:
            return bool(flag.get("enabled", False))
        body = r.stdout.decode("utf-8", errors="replace")
        enabled = bool(json.loads(body).get("enabled", False))
    except Exception:
        return bool(flag.get("enabled", False))

    cache["hook_discovery"] = {
        "enabled": enabled,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        DISCOVERY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = DISCOVERY_CACHE_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        os.replace(tmp, DISCOVERY_CACHE_PATH)
    except OSError:
        pass
    return enabled


def _install_sh_is_stale() -> bool:
    try:
        return (time.time() - DISCOVERY_INSTALL_SH.stat().st_mtime) > DISCOVERY_INSTALL_SH_TTL_SECONDS
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
    if not _hook_discovery_enabled_for_org():
        return
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
            print("{}")
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
