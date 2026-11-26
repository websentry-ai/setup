"""`unbound-hook setup` — in-binary port of mdm/onboard.py + per-tool MDM setup.

Orchestrates, in onboard.py's order: migration sweep (WEB-4788), then
claude-code, cursor, codex, copilot, then the discovery scan. All heavy
lifting reuses the vendored MDM setup modules' own functions (privilege
drop, env vars, config writes, user-hook strips, backfill, completion
notify); only two things differ from the python path by design:

  1. nothing is downloaded — no SCRIPT_URL fetches, no install.sh; the hook
     IS this binary and discovery is the locally installed binary
  2. managed hook settings point at
     /opt/unbound/current/unbound-hook/unbound-hook hook <tool> <event>
     with the per-event timeouts copied verbatim from the python writers
     (including PreToolUse's historical `15000` vs `60` elsewhere — units
     intentionally NOT normalized)

Fail-open: a component failure is reported in the summary and the exit code,
but never aborts the remaining components.
"""

import functools
import json
import math
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from ._loader import load_mdm_setup_module
from ._resources import (
    DISCOVERY_BINARY,
    HOOK_BINARY,
    hook_command_for_event,
    hook_source_path,
)
from . import migration

# Mirrors mdm/onboard.py's discovery timeout contract.
DISCOVERY_TIMEOUT_SECONDS = 5400
DISCOVERY_KILL_GRACE_SECONDS = 120

SETUP_TOOLS = ("claude-code", "cursor", "codex", "copilot", "augment")

USAGE = (
    "Usage: unbound-hook setup --api-key <admin_key>\n"
    "           [--backend-url <url>] [--gateway-url <url>] [--frontend-url <url>]\n"
    "           [--app_name <name>] [--backfill] [--tools t1,t2,...]\n"
    "           [--skip-managed-settings]   # claude-code only\n"
)


def _parse_args(argv):
    opts = {
        "api_key": None,
        "backend_url": "https://backend.getunbound.ai",
        "gateway_url": "https://api.getunbound.ai",
        "frontend_url": None,
        "app_name": None,
        "backfill": False,
        "skip_managed_settings": False,
        "tools": list(SETUP_TOOLS),
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--api-key" and i + 1 < len(argv):
            opts["api_key"] = argv[i + 1]; i += 2
        elif a == "--discovery-key":
            # Accepted and ignored so older callers keep working. A valueless
            # flag must not swallow the flag that follows it.
            i += 2 if i + 1 < len(argv) and not argv[i + 1].startswith("--") else 1
        elif a == "--backend-url" and i + 1 < len(argv):
            opts["backend_url"] = argv[i + 1]; i += 2
        elif a == "--gateway-url" and i + 1 < len(argv):
            opts["gateway_url"] = argv[i + 1]; i += 2
        elif a == "--frontend-url" and i + 1 < len(argv):
            opts["frontend_url"] = argv[i + 1]; i += 2
        elif a == "--app_name" and i + 1 < len(argv):
            opts["app_name"] = argv[i + 1]; i += 2
        elif a == "--backfill":
            opts["backfill"] = True; i += 1
        elif a == "--skip-managed-settings":
            # Read by the claude-code adapter alone; the other tools' managed
            # configs are unrelated to the Claude Code remote policy.
            opts["skip_managed_settings"] = True; i += 1
        elif a == "--tools" and i + 1 < len(argv):
            opts["tools"] = [t.strip() for t in argv[i + 1].split(",") if t.strip()]
            i += 2
        elif a == "--debug":
            i += 1
        else:
            print(f"Unknown argument: {a}", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return None
    return opts


# Reports about this run (start/end, hook errors) must never hold setup up.
REPORT_TIMEOUT_SECONDS = 5


def _post_json(url, body, headers, timeout=REPORT_TIMEOUT_SECONDS):
    """POST a JSON body with curl (the system trust store, as every call here uses).
    Returns (http status, response bytes); status 0 when nothing came back. Never raises.
    The headers carry keys, and any local user can read a process's argv, so they go to
    curl in a 0600 file (-H @file) that is removed afterwards."""
    header_file = None
    try:
        fd, header_file = tempfile.mkstemp(prefix=".unbound-headers.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("".join(f"{name}: {value}\n" for name, value in
                            {"Content-Type": "application/json", **headers}.items()))
        cmd = ["curl", "-sS", "-m", str(timeout), "-X", "POST", "-w", "\n%{http_code}",
               "-H", f"@{header_file}", "--data-binary", "@-", "--", url]
        result = subprocess.run(cmd, input=json.dumps(body).encode("utf-8"),
                                capture_output=True, timeout=timeout + 3)
        answer, _, code = (result.stdout or b"").rpartition(b"\n")
        return int(code.strip() or 0), answer
    except Exception:
        return 0, b""
    finally:
        if header_file:
            try:
                os.unlink(header_file)
            except OSError:
                pass


def _module(tool):
    m = load_mdm_setup_module(tool)
    m.DEBUG = True  # MDM runs always log diagnostics (parity with python path)
    return m


def _normalized_urls(m, opts):
    base = m.normalize_url(opts["backend_url"])
    gateway = m.normalize_url(opts["gateway_url"])
    return base, gateway


def _write_user_config(m, opts, username, home_dir, api_key) -> bool:
    """Every adapter's per-user ~/.unbound/config.json write, tallied per home for the end report:
    a home counts as configured only if every tool that reached it wrote there."""
    base, gateway = _normalized_urls(m, opts)
    ok = m.write_unbound_config_for_user(
        username, home_dir, api_key,
        urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})
    writes = opts.setdefault("config_writes", {})
    writes[str(home_dir)] = writes.get(str(home_dir), True) and bool(ok)
    return ok


# ---------------------------------------------------------------------------
# Run reports (WEB-6392): the device's install report hears when this run
# started and how it ended, on the endpoint and admin key onboard.sh's exit
# report uses. Fail-open: a report that can't be sent logs one line.
# ---------------------------------------------------------------------------

INSTALL_REPORT_PATH = "/api/v1/automations/mdm/install-report/"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _report_input(fn, fallback, what):
    """A value only the run reports use: when it can't be had, the reports lose it, never the install."""
    try:
        return fn()
    except Exception as e:
        print(f"[report] {what} unavailable: {e}")
        return fallback


def _send_run_report(opts, serial, phase, fields) -> None:
    """fields is called here, inside the fail-open guard."""
    try:
        if not serial:  # the endpoint joins on it; without one the report is dropped anyway
            print(f"[report] install-report {phase} not sent: no device serial")
            return
        body = {"serial_number": serial, "phase": phase,
                "install_mode": "binary-skip" if opts["skip_managed_settings"] else "binary", **fields()}
        code, _ = _post_json(opts["backend_url"] + INSTALL_REPORT_PATH, body, {"X-API-KEY": opts["api_key"]})
        if not 200 <= code < 300:
            print(f"[report] install-report {phase} not sent: HTTP {code}")
    except Exception as e:
        print(f"[report] install-report {phase} not sent: {e}")


def _start_fields() -> dict:
    host = {"hostname": platform.node(), "arch": platform.machine()}
    return {"runtime_version": __version__,
            "os_version": platform.mac_ver()[0] or platform.release(),
            **{k: v for k, v in host.items() if v},
            "timestamps": {"started_at": _utc_now()}}


def _preflight_warnings(user_homes) -> list:
    """What this run can already tell will keep the device from reporting. user_homes None: unknown."""
    warnings = []
    if not HOOK_BINARY.is_file():  # every managed hook command points at it
        warnings.append(f"hook binary not found at {HOOK_BINARY}")
    if user_homes == []:
        warnings.append("no user homes found")
    return warnings


# ---------------------------------------------------------------------------
# Per-tool outcome (WEB-6392): every tool sends setup/complete every run,
# configured | skipped | deferred, with the reason setup prints.
# ---------------------------------------------------------------------------

_TOOL_TYPES = {"claude-code": "claude-code", "cursor": "cursor", "codex": "codex",
               "copilot": "copilot", "augment": "augment_code"}

# The machine root the installed check looks under; tests point it at a sandbox.
_MACHINE_ROOT = Path("/")


def _tool_installed(tool, user_homes) -> bool:
    """The tool's own MDM module answers (one check per tool, shared with the python setup), with the
    macOS rules: this binary runs on macOS only. A check that fails counts as installed."""
    try:
        return load_mdm_setup_module(tool).tool_installed(user_homes, system="darwin", machine_root=_MACHINE_ROOT)
    except Exception:
        return True


def _tool_reporter(opts, m, tool, api_key, **fields):
    """This tool's report call, kept in opts so run() can still report a setup that raises after it."""
    report = functools.partial(_report, m, tool, api_key, **fields)
    opts.setdefault("tool_reporters", {})[tool] = report
    return report


def _report_failed_setup(opts, tool, reason) -> tuple:
    """A tool's setup raised: send 'deferred' when it got far enough to report, and keep it as the status."""
    report = opts.get("tool_reporters", {}).get(tool)
    if report is not None:
        try:
            return report("deferred", reason)
        except Exception as e:
            print(f"[{tool}] deferred status not reported: {e}")
    return "deferred", reason


def _report(m, tool, api_key, status, reason=None, installed=True, **fields):
    """This tool's setup/complete call for the run; returns the (status, reason) it sent. Configured on a Mac
    without the tool (installed False, from the run's one check) reads skipped: its config is still written,
    so the hook works once the tool arrives."""
    if status == "configured" and not installed:
        status, reason = "skipped", f"{m.TOOL_NAME} is not installed"
    m.notify_setup_complete(api_key, _TOOL_TYPES[tool], status=status, reason=reason, **fields)
    return status, reason


def _end_fields(opts, user_homes, warnings) -> dict:
    fields = {"timestamps": {"completed_at": _utc_now()}, "preflight_warnings": warnings}
    if user_homes is not None:  # unknown homes send no counts rather than wrong ones
        writes = opts.get("config_writes", {})
        configured = sum(1 for _, home in user_homes if writes.get(str(home)) is True)
        fields["user_homes"] = {"configured": configured, "skipped": len(user_homes) - configured}
    return fields


# ---------------------------------------------------------------------------
# Stuck hook errors (WEB-6392): a hook reports an error to the gateway at most
# once a minute and never retries, so the rest wait in its error.log. Each run
# sends the entries newer than the last one forwarded, per tool and per home.
# ---------------------------------------------------------------------------

# Each tool's hook log under a home, and the hook_source its hook reports as.
_HOOK_ERROR_LOGS = {
    "claude-code": (".claude/hooks/error.log", "claude-code"),
    "cursor": (".cursor/hooks/error.log", "cursor"),
    "codex": (".codex/hooks/error.log", "codex"),
    "copilot": (".copilot/hooks/error.log", "copilot"),
    "augment": (".augment/hooks/error.log", "augment_code"),
}
# Beside each error.log: "<timestamp> <n>", the newest entry the gateway accepted and how many entries
# stamped exactly then were sent (two can share a stamp, and a request can end between them).
FORWARDED_STATE_NAME = ".error_log_forwarded"
# Tools whose error.log lives in a folder the migration sweep and the tool step remove (~/.cursor/hooks).
_SWEPT_HOOK_LOG_TOOLS = ("cursor",)
HOOK_ERRORS_PER_REQUEST = 10  # the gateway takes at most ten
# error.log is the user's to write: per tool and home, a run sends at most the newest 25 (what a hook keeps)
# and nothing older than a week, so a flooded or first-seen log costs at most three requests.
HOOK_ERRORS_PER_RUN = 25
HOOK_ERROR_MAX_AGE = timedelta(days=7)
# Sentry groups by category: forwarded entries group together, apart from the hook's live reports.
FORWARDED_ERROR_CATEGORY = "forwarded_error_log"
_HOOK_ERROR_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})): (.*)$")


def _log_time(text):
    """An entry's timestamp as an aware datetime (hooks write UTC 'Z' or local time with its offset), else None."""
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else None


def _forwarded_place(log: Path):
    """(timestamp, how many entries stamped then were sent) from the state file; (None, 0) for none.
    A bare timestamp, as written before the count, means every entry stamped then was sent."""
    try:
        parts = _read_user_file(log.with_name(FORWARDED_STATE_NAME), follow=False).decode().split()
    except (OSError, UnicodeDecodeError):
        return None, 0
    last = _log_time(parts[0]) if parts else None
    sent_then = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else float("inf")
    return last, sent_then if last else 0


def _unsent_hook_errors(log: Path) -> list:
    """Runs as the profile's user: the newest HOOK_ERRORS_PER_RUN entries after the last one forwarded and
    newer than HOOK_ERROR_MAX_AGE, oldest first. Each carries the 'state' to save once it is sent."""
    floor = datetime.now(timezone.utc) - HOOK_ERROR_MAX_AGE
    last, sent_then = _forwarded_place(log)
    entries, seen_then, current = [], 0, None
    for line in _read_user_file_tail(log, _USER_FILE_MAX_BYTES).decode("utf-8", "replace").splitlines():
        match = _HOOK_ERROR_LINE.match(line)
        if not match:  # a message's own later lines (a traceback); they go with the entry they follow
            if current is not None:
                current["message"] = (current["message"] + "\n" + line)[:2000]
            continue
        when, current = _log_time(match.group(1)), None
        if when is None or when <= floor:
            continue
        if last is not None and when <= last:
            seen_then += when == last
            if when < last or seen_then <= sent_then:
                continue  # sent already
        current = {"timestamp": match.group(1), "message": match.group(2)[:2000],
                   "category": FORWARDED_ERROR_CATEGORY}
        entries.append((when, current))
    entries.sort(key=lambda entry: entry[0])  # stable: entries sharing a stamp keep the log's order
    chosen = entries[-HOOK_ERRORS_PER_RUN:]
    for i, (when, entry) in enumerate(chosen):
        same = sum(1 for other, _ in chosen[:i + 1] if other == when) + (sent_then if when == last else 0)
        entry["state"] = f"{entry['timestamp']} {same}"
    return [entry for _, entry in chosen]


def _save_forwarded(log: Path, state: str) -> bool:
    """Runs as the profile's user."""
    _replace_user_file(log.with_name(FORWARDED_STATE_NAME), state.encode("utf-8"), 0o600)
    return True


_BEARER = re.compile(r"(?i)\bBearer\s+\S+")
_NAMED_SECRET = re.compile(r"""(?i)\b([A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|passwd))("?\s*[:=]\s*"?)([^\s"',;&}]+)""")
_URL_SECRET = re.compile(r"(?i)([?&](?:key|token|api_key|access_token|sig|signature)=)[^&\s\"]+")
_VENDOR_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}")


def _redact_hook_error(message: str, secrets) -> str:
    """The home's own keys, then common credential shapes, each value replaced and its name kept."""
    for secret in secrets:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    message = _BEARER.sub("Bearer [REDACTED]", message)
    message = _NAMED_SECRET.sub(r"\1\2[REDACTED]", message)
    message = _URL_SECRET.sub(r"\1[REDACTED]", message)
    return _VENDOR_KEY.sub("[REDACTED]", message)


def _post_hook_errors(url, api_key, hook_source, hook_sha, batch, secrets=()) -> str:
    """The hook's own request shape and auth. 'sent' when the gateway took them; 'down' when it gave no
    answer or a 5xx; 'refused' when it answered no. It refuses only a key (200 with success false, or a
    4xx), never an entry, so a refusal is about this tool's key and not about what the log holds."""
    errors = [{**{k: v for k, v in entry.items() if k != "state"},
               "message": _redact_hook_error(entry["message"], (api_key, *secrets))}
              for entry in batch]
    code, answer = _post_json(url, {"errors": errors, "hook_source": hook_source, "hook_sha": hook_sha},
                              {"Authorization": f"Bearer {api_key}"})
    if code <= 0 or code >= 500:
        return "down"
    try:
        taken = 200 <= code < 300 and json.loads(answer.decode("utf-8")).get("success") is True
    except (ValueError, AttributeError):
        taken = False
    return "sent" if taken else "refused"


def _forward_home_errors(m, username, log, send):
    """(entries sent, 'sent' or the verdict that stopped it, whether every unsent entry went out). The place
    is saved after each accepted request; where it can't be saved nothing more is sent, or every run would
    send the same entries again."""
    if _as_user(m, username, _writable_dir, log.parent) is not True:
        print(f"[errors] {log} skipped: its forwarded place can't be saved beside it")
        return 0, "sent", False
    entries = _as_user(m, username, _unsent_hook_errors, log)
    if entries is None:
        return 0, "sent", False
    for start in range(0, len(entries), HOOK_ERRORS_PER_REQUEST):
        batch = entries[start:start + HOOK_ERRORS_PER_REQUEST]
        verdict = send(batch)
        if verdict != "sent":
            return start, verdict, False
        if _as_user(m, username, _save_forwarded, log, batch[-1]["state"]) is not True:
            print(f"[errors] {log}: forwarded place not saved; the rest waits for the next run")
            return start + len(batch), "sent", False
    return len(entries), "sent", True


def _set_aside_name(path: Path) -> Path:
    return path.parent.parent / f".unbound-unsent-{path.parent.name}-{path.name}"


def _set_aside_unsent_log(log: Path) -> list:
    """Runs as the profile's user: move the log and its forwarded place out of the folder the sweep removes,
    by rename so any size moves. Returns the names moved."""
    moved = []
    for path in (log, log.with_name(FORWARDED_STATE_NAME)):
        try:
            if os.path.lexists(path):
                os.rename(path, _set_aside_name(path))
                moved.append(path.name)
        except OSError:
            continue
    return moved


def _append_user_file(path: Path, data: bytes) -> None:
    """Runs as the profile's user: add data to the end of a regular file, on a line of its own."""
    fd = os.open(str(path), os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                data = b"\n" + data
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


def _restore_unsent_log(log: Path, names: list) -> bool:
    """Runs as the profile's user: move a set-aside log and its place back for the next run. A hook can
    write a new log while the old one is aside: its entries go after the set-aside ones, so both are kept."""
    log.parent.mkdir(mode=0o700, exist_ok=True)
    for name in names:
        path = log.with_name(name)
        if os.path.lexists(path):
            if name != log.name:
                continue  # setup writes the forwarded place, never a hook
            _append_user_file(_set_aside_name(path), _read_user_file(path, follow=False))
        os.replace(_set_aside_name(path), path)
    return True


def _recover_set_aside_log(log: Path) -> bool:
    """Runs as the profile's user: put back a log an earlier run set aside and could not restore."""
    return _restore_unsent_log(log, [p.name for p in (log, log.with_name(FORWARDED_STATE_NAME))
                                     if os.path.lexists(_set_aside_name(p))])


def _home_device_key(home: Path):
    """Runs as the profile's user: (the key its hooks report errors with, every key in ~/.unbound/config.json
    to redact), or None before setup first wrote it."""
    try:
        config = json.loads(_read_user_file(home / ".unbound" / "config.json", follow=False).decode("utf-8"))
    except (OSError, ValueError):
        return None
    # The hooks' own order (cfg.get('api_key') or cfg.get('device_token')): their errors are this key's.
    if not isinstance(config, dict):
        return None
    key = config.get("api_key") or config.get("device_token")
    secrets = tuple(v for v in (config.get("api_key"), config.get("device_token")) if isinstance(v, str) and v)
    return (key, secrets) if isinstance(key, str) and key else None


def _forward_hook_errors(m, tool, opts, user_homes=None, keys=None) -> None:
    """Forward every home's unsent error.log entries for this tool, with that home's own device key. Runs
    before the migration sweep, which removes ~/.cursor/hooks and its log. A gateway that is down ends
    forwarding for the whole run, so it costs one short timeout; a refused key is that home's own and skips
    only that home. Either way nothing is marked sent, and the next run retries. user_homes and keys (home
    to its key, filled as homes are read) come from run(), so each home is found and read once a run."""
    relpath, hook_source = _HOOK_ERROR_LOGS[tool]
    # Only a log in a folder the migration sweep removes needs keeping; the others stay where they are.
    unsent = opts.setdefault("unsent_hook_logs", []) if tool in _SWEPT_HOOK_LOG_TOOLS else []
    sent = 0
    try:
        hook_sha = (m.hook_script_hash(hook_source_path(tool)) or "unknown")[:12]
        keys = {} if keys is None else keys
        for username, home_dir in user_homes if user_homes is not None else m.get_all_user_homes():
            log = home_dir / relpath if home_dir is not None else None
            if log is not None and tool in _SWEPT_HOOK_LOG_TOOLS and os.path.lexists(_set_aside_name(log)):
                _as_user(m, username, _recover_set_aside_log, log)  # an earlier run could not put it back
            if log is None or not os.path.lexists(log):
                continue
            if opts.get("hook_errors_held"):
                unsent.append((username, log))  # the gateway is down: keep it for the next run
                continue
            if str(home_dir) not in keys:
                keys[str(home_dir)] = _as_user(m, username, _home_device_key, home_dir)
            found = keys[str(home_dir)]
            if not found:
                unsent.append((username, log))  # no hook here has a key to report with yet
                continue
            api_key, secrets = found
            send = functools.partial(_post_hook_errors, opts["gateway_url"] + "/v1/hooks/errors",
                                     api_key, hook_source, hook_sha, secrets=secrets)
            count, verdict, done = _forward_home_errors(m, username, log, send)
            sent += count
            if not done:
                unsent.append((username, log))
            if verdict == "refused":
                print(f"[errors] {tool} hook errors in {home_dir} not forwarded (key refused); the next run retries")
            elif verdict == "down":
                opts["hook_errors_held"] = True
                print(f"[errors] {tool} hook errors not forwarded (gateway down); the next run retries")
    except Exception as e:
        print(f"[errors] {tool} hook errors not forwarded: {e}")
    if sent:
        print(f"[errors] forwarded {sent} {tool} hook errors")


def _detect_state(settings_path: Path, expected_hooks, relative_ok=False):
    """'persisted' if every event runs our exact command (or the python-era unbound.py being migrated),
    'tampered' otherwise or if unparsable, 'fresh' with no file, None if unreadable. Admin-owned files only."""
    try:
        data = _read_user_file(settings_path, follow=True)
    except FileNotFoundError:
        return "fresh"
    except Exception as e:
        # None = "unknown" — notify_setup_complete omits the field entirely,
        # which is more honest than guessing 'fresh' over an unreadable but
        # real install. Loud so fleet logs show WHY the state was unknown.
        print(f"[setup] install_state detection failed for {settings_path}: {e}",
              file=sys.stderr)
        return None
    try:
        settings = _strict_json(data.decode("utf-8"))
    except (ValueError, RecursionError):  # the tool can't load it either
        return "tampered"
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    script = settings_path.parent / "hooks" / "unbound.py"  # where the python era kept it
    commands = _python_era_commands(script, settings_path.parent if relative_ok else None)
    grouped = not relative_ok  # Cursor (the only relative one) runs flat handlers only
    if _holds_every_entry(hooks, expected_hooks) or (
            script.is_file() and not script.is_symlink()
            # the agents' users must read and run it, and get through each folder to it
            and script.stat().st_mode & 0o005 == 0o005
            and all(os.stat(d).st_mode & 0o001 for d in (settings_path.parent, script.parent))
            and _runs_on_every_event(
                hooks, expected_hooks,
                lambda h: h.get("type", "command") == "command" and h["command"] in commands,
                grouped=grouped)):
        return "persisted"
    return "tampered"


def _strict_json(text):
    """JSON as these tools' JavaScript parsers read it: NaN and Infinity, which Python
    accepts, make them reject the whole file."""
    def _constant(name):
        raise ValueError(name)
    return json.loads(text, parse_constant=_constant)


def _holds_every_entry(hooks, expected_hooks) -> bool:
    """Every event still holds an entry that enforces like ours, so a release that tweaks a timeout or adds
    a field doesn't read as tampering (detection runs before the rewrite)."""
    return isinstance(hooks, dict) and all(
        isinstance(hooks.get(event), list)
        and all(any(_same_entry(actual, entry) for actual in hooks[event]) for entry in entries)
        for event, entries in expected_hooks.items())


def _same_entry(actual, ours) -> bool:
    """Enforces like ours: a flat handler like ours; or a group with our matcher, a
    handler like ours (beside any an organisation added) and our metadata flags."""
    if not isinstance(actual, dict):
        return False
    if "hooks" not in ours:
        return _handler_like(actual, ours)
    have = actual.get("metadata") if isinstance(actual.get("metadata"), dict) else {}
    return (actual.get("matcher") == ours.get("matcher")
            and isinstance(actual.get("hooks"), list)
            and all(any(_handler_like(h, o) for h in actual["hooks"]) for o in ours["hooks"])
            and all(have.get(k) == v for k, v in (ours.get("metadata") or {}).items()))


def _handler_like(handler, ours) -> bool:
    """The same type and commands (command, bash, powershell) wherever ours sets them,
    and no weaker."""
    return (isinstance(handler, dict)
            and all(handler.get(k) == ours[k] for k in ("type", "command", "bash", "powershell") if k in ours)
            and _no_weaker(handler, ours))


def _runs_on_every_event(hooks, expected_hooks, runs, grouped=True) -> bool:
    """Every event has a handler passing ``runs`` (a python-era install being migrated), flat or in a
    match-all group, no less able to block than ours: not async where ours isn't, no shorter timeout."""
    if not isinstance(hooks, dict):
        return False
    for event, entries in expected_hooks.items():
        ours = entries[0]["hooks"][0] if "hooks" in entries[0] else entries[0]
        flags = entries[0].get("metadata") or {}
        handlers = []
        for entry in hooks.get(event) if isinstance(hooks.get(event), list) else []:
            if isinstance(entry, dict) and "hooks" in entry:
                if not grouped:
                    continue  # this tool runs only flat handlers
                have = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
                if (entry.get("matcher") in (None, "", "*", ".*") and isinstance(entry["hooks"], list)
                        and all(have.get(k) == v for k, v in flags.items())):  # e.g. Augment's capture flags
                    handlers += entry["hooks"]
            else:
                handlers.append(entry)
        if not any(isinstance(h, dict) and isinstance(h.get("command"), str) and runs(h)
                   and _no_weaker(h, ours) for h in handlers):
            return False
    return True


def _no_weaker(handler, ours) -> bool:
    """Not async where ours isn't, and at least our timeout wherever we set one (Copilot fails a killed hook open).
    A release that raises a timeout must accept the old value for a release, or every device reads tampered."""
    if handler.get("async") is True and ours.get("async") is not True:
        return False
    for key in ("timeout", "timeoutSec"):
        mine, theirs = ours.get(key), handler.get(key)
        if isinstance(mine, int) and not (
                isinstance(theirs, int) and not isinstance(theirs, bool) and theirs >= mine):
            return False
    return True


def _python_era_commands(script: Path, base) -> set:
    """Exactly a command the macOS python installers wrote to run ``script``: quoted, bare, or relative to the
    settings folder (Cursor). Anything more (a pipe, a redirect, a flag) can discard the hook's answer."""
    shapes = set()
    if not any(ch in '$`\\"' for ch in str(script)):
        shapes.add(f'"{script}"')  # double quotes still expand these
    if not any(ch.isspace() or ch in _SHELL_SPECIAL for ch in str(script)):
        shapes.add(str(script))  # bare only where the shell keeps it one word
    if base is not None:  # Cursor runs hooks from the settings folder
        try:
            shapes.add("./" + script.relative_to(base).as_posix())
        except ValueError:
            pass
    return shapes


def _remove_stale_managed_script(managed_dir: Path) -> None:
    """Delete the python-era managed hook script — called ONLY after the
    settings rewrite succeeded, so hook registrations are never left
    pointing at a deleted script (a failed setup must leave the python
    serving path intact)."""
    script = managed_dir / "hooks" / "unbound.py"
    try:
        if script.is_file():
            script.unlink()
            print(f"[migration] removed {script}")
        hooks_dir = script.parent
        if hooks_dir.is_dir() and not any(hooks_dir.iterdir()):
            hooks_dir.rmdir()
    except OSError as e:
        print(f"[migration] could not remove {script}: {e}")


# ---------------------------------------------------------------------------
# Managed hook settings writers (binary command variants of the python
# setup_managed_hooks / setup_hooks / _copilot_hooks_config writers; JSON
# structure and timeouts copied verbatim, command strings swapped).
# ---------------------------------------------------------------------------

def _atomic_write_text(path: Path, text: str) -> None:
    """tmp + os.replace so a crash mid-write never leaves the editor reading
    a truncated managed-settings file. A link is refused, not resolved: this runs as
    root, so following one writes wherever it points."""
    if path.is_symlink():
        raise OSError(f"{path} is a link; refusing to write through it as root")
    tmp = path.parent / f"{path.name}.{os.getpid()}.tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)

def _claude_hooks_config():
    cmd = lambda ev: hook_command_for_event("claude-code", ev)
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "async": True, "timeout": 60}]}],
        # Claude reports a shell call that failed here instead, such as a command that exits non-zero.
        "PostToolUseFailure": [{"matcher": "Bash|PowerShell", "hooks": [
            {"type": "command", "command": cmd("PostToolUseFailure"), "async": True, "timeout": 60}]}],
        "UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": cmd("UserPromptSubmit"), "timeout": 60}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 60}]}],
        "SessionStart": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("SessionStart"), "async": True, "timeout": 60}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": cmd("SessionEnd"), "async": True, "timeout": 60}]}],
    }


# Events a release added; an install from before it lacks them, so for a release they are written but not
# required, or every such device would read as tampered.
_CLAUDE_EVENTS_ADDED = ("PostToolUseFailure",)


def _claude_detected_hooks():
    """The Claude Code hooks an install must already hold to read as persisted."""
    return {event: entries for event, entries in _claude_hooks_config().items() if event not in _CLAUDE_EVENTS_ADDED}


def _codex_hooks_config(hook_command):
    # Codex runs the command as a single on-disk python program (its python
    # path registers a bare script, not a shell line), so every event shares
    # one wrapper command; the event is read from stdin.
    cmd = lambda ev: hook_command
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "timeout": 60}]}],
        "UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": cmd("UserPromptSubmit"), "timeout": 60}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 60}]}],
        "SessionStart": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("SessionStart"), "timeout": 60}]}],
    }


def _strip_codex_user_hooks(m, username, home_dir) -> None:
    """As the user, remove our per-user entry and script, keeping their own hooks. A dotfiles link is
    updated where it points. A file that can't be read safely is left, with the script it may name."""
    hooks_path = home_dir / ".codex" / "hooks.json"
    wrapper = home_dir / ".codex" / "hooks" / "unbound.py"
    command = _codex_system_hooks_config()["Stop"][0]["hooks"][0]["command"]
    ours = lambda cmd: cmd == command or _codex_runs_wrapper(cmd, wrapper)

    def _strip():
        try:
            config = _load_codex_json(_read_user_file(hooks_path, follow=True))
        except FileNotFoundError:
            config = None
        except (OSError, ValueError, RecursionError):
            return False
        hooks = config.get("hooks") if isinstance(config, dict) else None
        changed = False
        for event, groups in (hooks.items() if isinstance(hooks, dict) else ()):
            if not isinstance(groups, list):
                continue
            kept = []
            for group in groups:
                handlers = group.get("hooks") if isinstance(group, dict) else None
                if isinstance(handlers, list):
                    rest = [h for h in handlers if not (isinstance(h, dict) and ours(h.get("command")))]
                    if len(rest) != len(handlers):
                        changed = True
                        if not rest:
                            continue
                        group = {**group, "hooks": rest}
                kept.append(group)
            hooks[event] = kept
        if changed:
            target = Path(os.path.realpath(hooks_path))
            try:
                text = json.dumps(config, indent=2, ensure_ascii=False, allow_nan=False)
            except RecursionError:  # indent uses the recursive pure-Python encoder
                text = json.dumps(config, ensure_ascii=False, allow_nan=False)
            _replace_user_file(target, text.encode("utf-8"), stat.S_IMODE(os.lstat(target).st_mode))
        if os.path.lexists(wrapper) and not os.path.isdir(wrapper):
            os.unlink(wrapper)
        return True

    _as_user(m, username, _strip)


def _codex_system_hooks_config():
    """Our hooks for codex's system hooks.json; codex runs the command through the user's shell."""
    return _codex_hooks_config(f'"{HOOK_BINARY}" hook codex')


def _write_codex_system_hooks(m) -> bool:
    """Merge our hooks into codex's system hooks.json, keeping any other hooks there. Codex runs this file
    as a managed hook for every user, with no trust prompt, and only root can change it."""
    try:
        managed_dir = m.get_managed_settings_dir()
        path = managed_dir / "hooks.json"
        script = managed_dir / "hooks" / "unbound.py"  # where a python-era install kept it
        command = _codex_system_hooks_config()["Stop"][0]["hooks"][0]["command"]
        try:
            existing = _load_codex_json(path.read_bytes()) if path.is_file() else {}
        except (OSError, ValueError, RecursionError):
            existing = {}
        if not _codex_can_load(existing):
            # codex refuses the whole file; keep what it can load and drop only the broken pieces
            existing = {k: v for k, v in _codex_make_loadable(existing).items() if k in _CODEX_FILE_FIELDS}
            hooks = {e: g for e, g in existing.get("hooks", {}).items() if e in _CODEX_EVENT_FIELDS}
            for event, groups in hooks.items():
                for group in groups:
                    if isinstance(group.get("hooks"), list):  # a type this codex doesn't know fails it too
                        group["hooks"] = [h for h in group["hooks"] if _codex_handler_loads(h)]
                hooks[event] = [g for g in groups if g.get("hooks") != []]
            existing["hooks"] = hooks
            if not _codex_can_load(existing):
                existing = {}
        hooks = dict(existing.get("hooks") or {})
        for event, groups in _codex_system_hooks_config().items():
            kept = []
            for group in hooks.get(event) if isinstance(hooks.get(event), list) else []:
                handlers = group.get("hooks") if isinstance(group, dict) else None
                if isinstance(handlers, list):
                    mine = [h for h in handlers if isinstance(h, dict) and (
                        h.get("command") == command or _codex_runs_wrapper(h.get("command"), script))]
                    if mine and len(mine) == len(handlers):
                        continue
                    if mine:
                        group = {**group, "hooks": [h for h in handlers if h not in mine]}
                kept.append(group)
            hooks[event] = kept + groups
        config = {"hooks": hooks}
        if "description" in existing:
            config["description"] = existing["description"]
        managed_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(path, json.dumps(config, indent=2))
        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)  # codex reads it as each user, whatever root's umask
            os.chmod(path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write codex system hooks.json: {e}")
        return False


def _cursor_hooks_json():
    """cursor/hooks.json with binary commands; events/timeouts verbatim."""
    cmd = lambda ev: hook_command_for_event("cursor", ev)
    hooks = {
        "preToolUse": [{"command": cmd("preToolUse"), "timeout": 15000}],
        "postToolUse": [{"command": cmd("postToolUse")}],
        "beforeShellExecution": [{"command": cmd("beforeShellExecution"), "timeout": 15000}],
        "beforeMCPExecution": [{"command": cmd("beforeMCPExecution"), "timeout": 15000}],
        "afterShellExecution": [{"command": cmd("afterShellExecution")}],
        "afterMCPExecution": [{"command": cmd("afterMCPExecution")}],
        "afterFileEdit": [{"command": cmd("afterFileEdit")}],
        "beforeReadFile": [{"command": cmd("beforeReadFile")}],
        "beforeSubmitPrompt": [{"command": cmd("beforeSubmitPrompt")}],
        "afterAgentResponse": [{"command": cmd("afterAgentResponse")}],
        "stop": [{"command": cmd("stop")}],
        "sessionStart": [{"command": cmd("sessionStart")}],
    }
    return {"version": 1, "hooks": hooks}


def _augment_hooks_config():
    """The Augment hooks block with binary commands. Structure + per-event
    timeouts (ms) copied verbatim from augment build_hooks_block; block-level
    metadata is set by the writer and no UserPromptSubmit (Augment has no such
    event). No Windows `shell` key — the binary path is macOS-only."""
    cmd = lambda ev: hook_command_for_event("augment", ev)
    return {
        "PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "timeout": 10000}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 10000}]}],
        "SessionStart": [{"hooks": [
            {"type": "command", "command": cmd("SessionStart"), "timeout": 60000}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": cmd("SessionEnd"), "timeout": 10000}]}],
    }


def _augment_written_hooks(m):
    """The Augment hooks as the writer leaves them: our groups plus the metadata flags
    it sets on them."""
    hooks = _augment_hooks_config()
    for event, flags in m._HOOK_METADATA.items():
        for group in hooks.get(event, []):
            group["metadata"] = dict(flags)
    return hooks


def _copilot_hooks_config():
    """Port of _copilot_hooks_config with the binary command. Copilot is
    invoked per-user; field pairs (command/bash/powershell, timeout/
    timeoutSec) preserved verbatim."""
    event_timeouts = {
        "SessionStart": 30,
        "UserPromptSubmit": 60,
        "PreToolUse": 600,
        "PostToolUse": 30,
        "Stop": 60,
    }
    hooks = {}
    for event_name, timeout_sec in event_timeouts.items():
        cmd = hook_command_for_event("copilot", event_name)
        hooks[event_name] = [{
            "type": "command",
            "command": cmd,
            "bash": cmd,
            "powershell": cmd,
            "timeout": timeout_sec,
            "timeoutSec": timeout_sec,
        }]
    return {"version": 1, "hooks": hooks}


def _print_remote_policy_hooks() -> None:
    """One command per event, unlike the python path's single script path —
    an admin authoring the remote policy needs every one of them."""
    print("Add these to your remote Claude Code policy:")
    for event, entries in _claude_hooks_config().items():
        for entry in entries:
            for hook in entry.get("hooks", []):
                print(f"  {event}: {hook['command']}")


def _write_claude_managed_settings(m, skip_settings: bool = False) -> bool:
    """Binary variant of claude-code setup_managed_hooks(): same settings
    file, same gateway-leftover cleanup, no script download. With
    skip_settings it writes no hook config and leaves the file alone entirely."""
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "managed-settings.json"

        # No hook config of our own: the remote policy owns it. managed-settings.json
        # belongs to the admin in this mode and is neither read nor written.
        if skip_settings:
            if platform.system().lower() in ("darwin", "linux"):
                os.chmod(managed_dir, 0o755)
            return True

        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    # Drop NaN/Infinity: the tool rejects the whole file over one.
                    settings = _drop_out_of_range(json.load(f) or {})
            except Exception:
                settings = {}

        # Same gateway-era cleanup as the python writer.
        if "apiKeyHelper" in settings:
            del settings["apiKeyHelper"]
        env = settings.get("env") if isinstance(settings.get("env"), dict) else None
        if env:
            for k in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
                env.pop(k, None)
            if not env:
                del settings["env"]

        settings["hooks"] = _claude_hooks_config()
        _atomic_write_text(settings_path, json.dumps(settings, indent=2))

        gateway_key_helper = managed_dir / "anthropic_key.sh"
        if gateway_key_helper.exists():
            try:
                gateway_key_helper.unlink()
            except Exception:
                pass

        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write managed settings: {e}")
        return False


def _write_augment_managed_settings(m) -> bool:
    """Binary variant of augment setup_managed_hooks(): same /etc/augment/
    settings.json, no script download. /etc/augment/settings.json is SHARED
    with the org's own Augment config, so this MERGES per-event (append our
    hook entry only if our command isn't already present) and merges
    toolPermissions on identity, preserving every foreign entry, rule, and
    other top-level key — never clobbering the org's config."""
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "settings.json"

        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    # Drop NaN/Infinity: the tool rejects the whole file over one.
                    settings = _drop_out_of_range(json.load(f) or {})
            except Exception:
                settings = {}
        if not isinstance(settings, dict):
            settings = {}

        # MERGE per-event (settings.json is shared with the org's own config):
        # append our hook entry per event only if our command isn't already
        # present; preserve every foreign entry and other top-level key.
        hooks_config = _augment_hooks_config()
        if not isinstance(settings.get("hooks"), dict):
            settings["hooks"] = {}
        for event, new_config in hooks_config.items():
            our_command = new_config[0]["hooks"][0]["command"]
            existing_config = settings["hooks"].get(event)
            if isinstance(existing_config, list):
                # Our group as written (metadata is set below). Take our handler out of any
                # other group, so a changed matcher or timeout is replaced, not kept beside it.
                ours = dict(new_config[0])
                our_hook_exists = any(_same_entry(item, ours) for item in existing_config)
                emptied = []
                for item in existing_config:
                    if isinstance(item, dict) and isinstance(item.get("hooks"), list) \
                            and not _same_entry(item, ours):
                        kept = [h for h in item["hooks"]
                                if not (isinstance(h, dict) and h.get("command") == our_command)]
                        if item["hooks"] and not kept:
                            emptied.append(id(item))  # ours alone: drop it; an org's empty group stays
                        item["hooks"] = kept
                existing_config[:] = [item for item in existing_config if id(item) not in emptied]
                if not our_hook_exists:
                    existing_config.extend(new_config)
            elif existing_config is None:
                settings["hooks"][event] = new_config
            # A foreign non-list hooks[event] is left untouched.

        # Without these Auggie sends no context, so no account email. Set on
        # existing blocks too, so installed devices pick them up on re-run.
        for event, flags in m._HOOK_METADATA.items():
            blocks = settings["hooks"].get(event)
            if not isinstance(blocks, list):
                continue
            our_command = hooks_config[event][0]["hooks"][0]["command"]
            for item in blocks:
                if isinstance(item, dict) and any(
                        isinstance(hook, dict) and hook.get("command", "") == our_command
                        # .get's default only covers a missing key, so a scalar
                        # would be iterated and raise, aborting the write.
                        for hook in (item.get("hooks")
                                     if isinstance(item.get("hooks"), list) else [])):
                    if not isinstance(item.get("metadata"), dict):
                        item["metadata"] = {}
                    item["metadata"].update(flags)

        # Merge toolPermissions, preserving foreign rules. Match on our identity
        # (toolName + shellInputRegex) so re-running never duplicates.
        existing_perms = settings.get("toolPermissions")
        if not isinstance(existing_perms, list):
            existing_perms = []
        existing_identities = {
            m._tool_permission_identity(r) for r in existing_perms if isinstance(r, dict)
        }
        for rule in m.build_tool_permissions_block():
            if m._tool_permission_identity(rule) not in existing_identities:
                existing_perms.append(rule)
                existing_identities.add(m._tool_permission_identity(rule))
        settings["toolPermissions"] = existing_perms

        _atomic_write_text(settings_path, json.dumps(settings, indent=2))

        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write augment managed settings: {e}")
        return False


# Files in a user's home: never follow a link we write through, and never wait
# on a FIFO planted in place of one.
_USER_FILE_WRITE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                          | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
_USER_FILE_MAX_BYTES = 4 * 1024 * 1024


def _read_user_file(path: Path, follow: bool) -> bytes:
    """A user-owned file's bytes, read non-blocking and capped. Raises OSError for
    anything but a regular file within the cap."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        data = f.read(_USER_FILE_MAX_BYTES + 1)
    if len(data) > _USER_FILE_MAX_BYTES:
        raise OSError(f"{path} is larger than {_USER_FILE_MAX_BYTES} bytes")
    return data


def _read_user_file_tail(path: Path, max_bytes: int) -> bytes:
    """A user-owned regular file's last max_bytes, from a whole line on: a long log is read from its end."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        if st.st_size <= max_bytes:
            return f.read(max_bytes)
        f.seek(st.st_size - max_bytes)
        data = f.read(max_bytes)
    return data.split(b"\n", 1)[1] if b"\n" in data else b""


class _JsonObject(dict):
    """A parsed JSON object that remembers which keys appeared more than once, and its
    nesting depth as serde_json reads it, including values a repeated key replaced."""
    dups = frozenset()


def _json_object(pairs):
    obj = _JsonObject(pairs)
    # Built bottom-up, so nested objects already know their depth: linear overall.
    obj.depth = 1 + max((_value_depth(v) for _, v in pairs), default=0)
    if len(obj) != len(pairs):
        seen, dups = set(), set()
        for key, _ in pairs:
            (dups if key in seen else seen).add(key)
        obj.dups = frozenset(dups)
    return obj


def _load_codex_json(data: bytes):
    """Parse as codex's serde_json would: reject a byte-order mark, NaN/Infinity, numbers past f64's range
    and lone surrogates. Duplicate keys are kept for the schema check."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte-order mark")

    def _constant(name):
        raise ValueError(name)

    def _number(parse):
        def checked(text):
            value = parse(text)
            if _out_of_range(value):
                raise ValueError("number out of range")
            return value
        return checked

    config = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_constant,
                        parse_float=_number(float), parse_int=_number(int))
    json.dumps(config, ensure_ascii=False).encode("utf-8")  # raises on a lone surrogate
    return config


_SERDE_MAX_DEPTH = 128  # serde_json fails on the 128th nested [ or {


# serde_json fails on the 128th nested [ or { only in values codex deserializes; the only nested one it
# reads is an mcp_tool handler's input (file > hooks > event > group > hooks > handler).
_SERDE_HANDLER_DEPTH = 6


def _value_depth(value) -> int:
    """Nesting serde_json walks to read ``value``, iteratively; a parsed object's own
    depth (which counts values a repeated key replaced) ends the walk there."""
    deepest, stack = 0, [(value, 0)]
    while stack:
        node, above = stack.pop()
        depth = getattr(node, "depth", None)
        if depth is not None:
            deepest = max(deepest, above + depth)
            continue
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else None
        if children is None:
            continue
        deepest = max(deepest, above + 1)
        stack.extend((child, above + 1) for child in children)
    return deepest


# Codex's hooks.json schema (codex-rs/config/src/hook_config.rs). It rejects the
# whole file if any of this fails to deserialize, and no hook in it runs.
_CODEX_FILE_FIELDS = ("description", "hooks")
_CODEX_EVENT_FIELDS = (
    "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact",
    "SessionStart", "SessionEnd", "UserPromptSubmit", "SubagentStart", "SubagentStop",
    "Stop", "Interrupt")
_CODEX_HANDLER_FIELDS = {
    "command": {"type": None, "command": str, "commandWindows": "str?", "command_windows": "str?",
                "timeout": "u64?", "async": bool, "statusMessage": "str?",
                "additionalContextLimit": "u64?"},
    "mcp_tool": {"type": None, "server": str, "tool": str, "input": "toml_map",
                 "timeout": "u64?", "statusMessage": "str?"},
    "prompt": {"type": None},
    "agent": {"type": None},
}
_U64_MAX = 2 ** 64 - 1


def _struct_ok(obj, fields) -> bool:
    """A serde-derived struct: a JSON object with no known field repeated."""
    return isinstance(obj, dict) and not (getattr(obj, "dups", frozenset()) & set(fields))


def _toml_ok(value) -> bool:
    if value is None:
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -2 ** 63 <= value < 2 ** 63
    if isinstance(value, list):
        return all(_toml_ok(v) for v in value)
    return isinstance(value, dict) and all(_toml_ok(v) for v in value.values())


def _field_ok(value, kind) -> bool:
    if kind is str:
        return isinstance(value, str)
    if kind is bool:
        return isinstance(value, bool)
    if kind == "str?":
        return value is None or isinstance(value, str)
    if kind == "u64?":
        return value is None or (isinstance(value, int) and not isinstance(value, bool)
                                 and 0 <= value <= _U64_MAX)
    if kind == "toml_map":
        # Depth first: it's iterative, and _toml_ok recurses.
        return (isinstance(value, dict) and _SERDE_HANDLER_DEPTH + _value_depth(value) < _SERDE_MAX_DEPTH
                and _toml_ok(value))
    return True


def _codex_handler_loads(handler) -> bool:
    kind = handler.get("type") if isinstance(handler, dict) else None
    fields = _CODEX_HANDLER_FIELDS.get(kind) if isinstance(kind, str) else None
    if fields is None or not _struct_ok(handler, fields):
        return False
    if "commandWindows" in handler and "command_windows" in handler:
        return False  # one field under two names
    required = [k for k, kind in fields.items() if kind in (str,)]
    return (all(k in handler for k in required)
            and all(_field_ok(handler[k], kind) for k, kind in fields.items() if k in handler))


def _codex_group_loads(group) -> bool:
    if not _struct_ok(group, ("matcher", "hooks")):
        return False
    if not _field_ok(group.get("matcher"), "str?"):
        return False
    hooks = group.get("hooks", [])
    return isinstance(hooks, list) and all(_codex_handler_loads(h) for h in hooks)


def _codex_can_load(config) -> bool:
    """Whether codex would load this hooks.json at all."""
    if not _struct_ok(config, _CODEX_FILE_FIELDS) or set(config) - set(_CODEX_FILE_FIELDS):
        return False
    if not _field_ok(config.get("description"), "str?"):
        return False
    events = config.get("hooks", {})
    if not _struct_ok(events, _CODEX_EVENT_FIELDS):
        return False
    return all(isinstance(events[e], list) and all(_codex_group_loads(g) for g in events[e])
               for e in _CODEX_EVENT_FIELDS if e in events)


def _codex_make_loadable(config) -> dict:
    """Drop only content that breaks codex's known schema, so the hooks it can load run again. Unknown keys
    and handler types are kept: a newer codex may define them."""
    if not isinstance(config, dict):
        return {}
    clean = dict(config)
    if not _field_ok(clean.get("description"), "str?"):
        clean.pop("description")
    events = clean.get("hooks")
    clean["hooks"] = events = dict(events) if isinstance(events, dict) else {}
    for event in _CODEX_EVENT_FIELDS:
        if event not in events:
            continue
        groups = events[event] if isinstance(events[event], list) else []
        kept = []
        for group in groups:
            if not isinstance(group, dict) or not _field_ok(group.get("matcher"), "str?"):
                continue
            group = dict(group)
            if "hooks" not in group:  # valid as is; adding the field would force a rewrite
                kept.append(group)
                continue
            hooks = group["hooks"]
            # dict(): a repeated field collapses to its last value, as on rewrite.
            group["hooks"] = ([dict(h) for h in hooks if isinstance(h, dict) and _codex_handler_kept(dict(h))]
                              if isinstance(hooks, list) else [])
            if group["hooks"] or not hooks:
                kept.append(group)
        events[event] = kept
    return _drop_out_of_range(clean)


def _codex_handler_kept(handler) -> bool:
    """Keep a handler unless it breaks the schema of a type we know."""
    kind = handler.get("type") if isinstance(handler, dict) else None
    if isinstance(kind, str) and kind not in _CODEX_HANDLER_FIELDS:
        return True
    return _codex_handler_loads(handler)


_F64_MAX_INT = int(sys.float_info.max)


def _out_of_range(value) -> bool:
    """A number serde_json rejects: NaN/Infinity, or an integer too large for an f64."""
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return abs(value) >= _F64_MAX_INT  # serde_json gives up at f64's limit; Python rounds below it
    return False


def _drop_out_of_range(value):
    """Drop numbers codex can't parse wherever they sit: one rejects the whole file.
    Iterative and in place, since a field codex skips can nest past Python's recursion."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key in [k for k, v in node.items() if _out_of_range(v)]:
                del node[key]
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            node[:] = [v for v in node if not _out_of_range(v)]
            stack.extend(v for v in node if isinstance(v, (dict, list)))
    return value


# The user a check runs as can pause it; setup's own checks and installs are quick.
_USER_CHECK_TIMEOUT = 30


def _as_user(m, username, fn, *args):
    """The module's _run_as_user, bounded: an answer of None (unknown) after the timeout. The claude-code,
    cursor and augment copies take no timeout (one passed would reach fn and fail every call), so those
    checks run through codex's copy, the same privilege drop with the bound."""
    if not hasattr(m, "_RUN_AS_USER_TIMEOUT"):  # set only where _run_as_user takes _timeout
        m = load_mdm_setup_module("codex")
    return m._run_as_user(username, fn, *args, _timeout=_USER_CHECK_TIMEOUT)


def _replace_user_file(path: Path, data: bytes, mode: int) -> None:
    """Write ``data`` beside ``path`` and rename it over: a symlink or FIFO there is replaced, not written
    through, and a failed write leaves the old file in place."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if os.path.lexists(tmp):
        tmp.unlink()
    fd = os.open(str(tmp), _USER_FILE_WRITE_FLAGS | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
        os.rename(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _command_targets_hook(command: str, target: Path) -> bool:
    if not isinstance(command, str) or not command:
        # A non-string command is not ours; the checks below would raise on it.
        return False
    try:
        tokens = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        return False
    tokens = [t.strip().strip('"').strip("'") for t in tokens]
    tokens = [t for t in tokens if t]
    if not tokens:
        return False
    launcher = os.path.basename(tokens[0]).lower()
    if launcher.endswith(".exe"):
        launcher = launcher[:-4]
    if launcher in ("py", "python", "python2", "python3"):
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]
    if not tokens:
        return False
    normalized_target = os.path.normcase(os.path.normpath(str(target)))
    return os.path.normcase(os.path.normpath(tokens[0])) == normalized_target


def _write_cursor_enterprise_hooks(m) -> tuple:
    """Binary variant of cursor setup_hooks(). Returns (ok, hooks_changed)."""
    try:
        enterprise_dir = m.get_enterprise_hooks_dir()
        hooks_json = enterprise_dir / "hooks.json"
        new_content = json.dumps(_cursor_hooks_json(), indent=2)
        hooks_changed = m.compare_hooks_json(hooks_json, new_content)
        enterprise_dir.mkdir(parents=True, exist_ok=True)
        tmp = enterprise_dir / "hooks.json.tmp"
        tmp.write_text(new_content, encoding="utf-8")
        tmp.replace(hooks_json)
        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(hooks_json, 0o644)
        return True, hooks_changed
    except Exception as e:
        print(f"Failed to write cursor hooks.json: {e}")
        return False, False


def _install_copilot_hooks_for_user(m, username, home_dir) -> bool:
    """Binary variant of copilot install_hooks_for_user(): writes only
    unbound.json (no unbound.py copy), privilege-dropped like the original.
    The python-era unbound.py is removed AFTER the new registration is
    written — a failed install leaves python-era coverage fully intact
    (same delete-after-replace rule as the managed-settings tools)."""
    hooks_dir = home_dir / ".copilot" / "hooks"
    hooks_json = hooks_dir / "unbound.json"
    stale_script = hooks_dir / "unbound.py"
    config = _copilot_hooks_config()

    def _install():
        hooks_dir.mkdir(parents=True, exist_ok=True)
        _replace_user_file(hooks_json, json.dumps(config, indent=2).encode("utf-8"), 0o644)
        try:
            if stale_script.is_file():
                stale_script.unlink()
        except OSError:
            pass  # stale script is inert once unbound.json points at the binary
        return True

    return bool(_as_user(m, username, _install))


# ---------------------------------------------------------------------------
# Per-tool adapters — each mirrors its python main() flow step-for-step,
# minus downloads, returning a status instead of exiting.
# ---------------------------------------------------------------------------

def _setup_claude_code(opts):
    m = _module("claude-code")
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")
    skip_settings = opts["skip_managed_settings"]
    report = _tool_reporter(opts, m, "claude-code", api_key, backend_url=base, serial_number=device_id,
                            installed=opts.get("installed", {}).get("claude-code", True),
                            install_mode="binary-skip" if skip_settings else "binary")

    for username, home_dir in m.get_all_user_homes():
        m.remove_env_var_from_user(username, home_dir, "UNBOUND_API_KEY")
        m.remove_env_var_from_user(username, home_dir, "ANTHROPIC_BASE_URL")

    config_ok = True
    for username, home_dir in m.get_all_user_homes():
        m.remove_gateway_artifacts_for_user(username, home_dir)
        m.remove_user_level_hooks_for_user(username, home_dir)
        config_ok = _write_user_config(m, opts, username, home_dir, api_key) and config_ok
    m.remove_legacy_key_env()

    # None (unknown) without looking: in skip mode managed-settings.json is the
    # admin's file, and unknown leaves the backend's tamper state untouched.
    state = None if skip_settings else _detect_state(
        m.get_managed_settings_dir() / "managed-settings.json", _claude_detected_hooks())
    if not _write_claude_managed_settings(m, skip_settings=skip_settings):
        return report("deferred", "managed settings update failed")
    if skip_settings:
        # A remote policy may name the python script; deleting it here would
        # strand that policy on a missing file with no local error.
        _print_remote_policy_hooks()
    else:
        _remove_stale_managed_script(m.get_managed_settings_dir())

    if not config_ok:
        return report("deferred", "config.json write failed for some users")

    # skip mode writes no hook config of its own: the remote policy holds it
    outcome = report("configured", install_state=state,
                     hook_hash=m.hook_script_hash(hook_source_path("claude-code")),
                     written_to=None if skip_settings else str(m.get_managed_settings_dir() / "managed-settings.json"))
    if opts["backfill"]:
        # Bounded like the MDM script: a heavy history must not hold setup open. The
        # deadline origin is this tool's turn, not module import in the shared process.
        m._SCRIPT_START = time.time()
        m._run_backfill_bounded(api_key, base, m.get_all_user_homes())
    return outcome


def _setup_augment(opts):
    """Mirrors augment mdm/setup.py main() step-for-step, minus downloads.
    Augment uses system-managed /etc/augment (get_managed_settings_dir), like
    claude-code; the notify tool_type is 'augment_code' (verbatim from
    augment's setup.py). Augment does NOT support backfill. One substitution from main(): user-level hook
    removal is gated on the managed write returning True rather than on
    verify_managed_hooks_installed() — the latter checks for the downloaded
    /etc/augment/hooks/unbound.py the binary path never writes."""
    m = _module("augment")
    base, gateway = _normalized_urls(m, opts)
    if opts["backfill"]:
        print("[backfill] Augment backfill is not supported.")
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")
    report = _tool_reporter(opts, m, "augment", api_key, backend_url=base, serial_number=device_id,
                            installed=opts.get("installed", {}).get("augment", True),
                            install_mode="binary")

    # Write the per-user unbound config now (needed by the managed hook). User
    # hook removal is deferred until the managed write succeeds (parity with
    # augment main()'s ordering).
    config_ok = True
    user_homes = m.get_all_user_homes()
    for username, home_dir in user_homes:
        config_ok = _write_user_config(m, opts, username, home_dir, api_key) and config_ok
    m.remove_legacy_key_env()

    state = _detect_state(m.get_managed_settings_dir() / "settings.json", _augment_written_hooks(m))
    if not _write_augment_managed_settings(m):
        return report("deferred", "managed settings write failed")
    _remove_stale_managed_script(m.get_managed_settings_dir())

    # Strip leftover user-level Unbound hooks only after the managed write
    # succeeded, so managed hooks don't fire twice.
    for username, home_dir in user_homes:
        m.remove_user_level_hooks_for_user(username, home_dir)

    if not config_ok:
        return report("deferred", "config.json write failed for some users")

    return report("configured", install_state=state, hook_hash=m.hook_script_hash(hook_source_path("augment")),
                  written_to=str(m.get_managed_settings_dir() / "settings.json"))


def _setup_codex(opts):
    m = _module("codex")
    m._RUN_AS_USER_TIMEOUT = _USER_CHECK_TIMEOUT  # until the report: a user can pause a call
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")
    report = _tool_reporter(opts, m, "codex", api_key, backend_url=base, serial_number=device_id,
                            installed=opts.get("installed", {}).get("codex", True),
                            install_mode="binary")

    for username, home_dir in m.get_all_user_homes():
        m.remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")


    # A user-level hook runs only after its user trusts it, so ours goes in codex's system
    # hooks.json instead, which codex runs as a managed hook. The per-user copy is removed
    # once that's written: codex doesn't de-duplicate, so a trusted one would run twice.
    user_homes = m.get_all_user_homes()
    state = _codex_detect_state(m, user_homes)
    if not _write_codex_system_hooks(m):
        return report("deferred", "codex system hooks.json write failed")
    config_ok = True
    for username, home_dir in user_homes:
        m.remove_gateway_artifacts_for_user(username, home_dir)
        config_ok = _write_user_config(m, opts, username, home_dir, api_key) and config_ok
        m.enable_codex_hooks_feature_for_user(username, home_dir)
        _strip_codex_user_hooks(m, username, home_dir)
    # After the new hooks are in place: an older codex hook reads only the per-tool var.
    m.remove_legacy_key_env()

    if not config_ok:
        return report("deferred", "config.json write failed for some users")

    outcome = report("configured", install_state=state, hook_hash=m.hook_script_hash(hook_source_path("codex")),
                     written_to=str(m.get_managed_settings_dir() / "hooks.json"))
    if opts["backfill"]:
        m._RUN_AS_USER_TIMEOUT = None  # a backfill takes as long as it takes
        m.run_backfill(api_key, base, m.get_all_user_homes())
    return outcome


# Characters the shell acts on in an unquoted word.
_SHELL_SPECIAL = set(" \t\n\"'\\$`;&|<>()*?[]{}~#!")
# Events where an async hook can't block, so codex wouldn't enforce our answer.
# Older installs wrote async only on PostToolUse and SessionStart.
_CODEX_BLOCKING_EVENTS = ("PreToolUse", "UserPromptSubmit", "Stop")
# Codex ignores the matcher on these (matcher_pattern_for_event).
_CODEX_UNMATCHED_EVENTS = ("UserPromptSubmit", "Stop", "Interrupt")


def _codex_runs_wrapper(command, wrapper: Path) -> bool:
    """The command is a way our installers write the wrapper: shell-quoted, or quoted or bare where the shell
    expands nothing. Anything else can expand, redirect or skip it."""
    if not isinstance(command, str):
        return False
    path = str(wrapper)
    forms = {shlex.quote(path)}
    if "'" not in path:
        forms.add(f"'{path}'")
    if not any(c in path for c in '"$`\\'):
        forms.add(f'"{path}"')
    if not any(c in _SHELL_SPECIAL for c in path):
        forms.add(path)
    return command in forms


def _codex_group_runs_wrapper(group, wrapper: Path, event: str) -> bool:
    """A group that fires our wrapper for every tool and lets it act: a match-all matcher (absent, "" or "*"),
    the exact command, synchronous where it blocks, and no shorter timeout than any we've written."""
    if not isinstance(group, dict):
        return False
    if event not in _CODEX_UNMATCHED_EVENTS and group.get("matcher") not in (None, "", "*"):
        return False
    floor = 10 if event == "PreToolUse" else 60
    hooks = group.get("hooks")
    for h in hooks if isinstance(hooks, list) else []:
        if not (isinstance(h, dict) and h.get("type") == "command"
                and _codex_runs_wrapper(h.get("command"), wrapper)):
            continue
        if h.get("async") and event in _CODEX_BLOCKING_EVENTS:
            continue
        timeout = h.get("timeout")  # an Option<u64>: null is unset, like a missing key
        timeout = floor if timeout is None else timeout
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < floor:
            continue
        return True
    return False


try:
    import tomllib
except ImportError:  # python older than 3.11; the shipped binary bundles it
    tomllib = None


def _codex_hooks_disabled(config_path: Path) -> bool:
    """Whether config.toml turns codex's hooks feature off (on by default; the legacy
    key codex_hooks is an alias), or codex can't load it at all, so no hook runs."""
    try:
        data = _read_user_file(config_path, follow=True)
    except FileNotFoundError:
        return False
    except OSError:
        return True  # a FIFO or oversized file can still hand codex hooks = false
    if tomllib is None:
        return False
    try:
        features = tomllib.loads(data.decode("utf-8")).get("features")
    except (ValueError, RecursionError):
        return True  # codex refuses the whole config, and setup won't rewrite it
    if features is None:
        return False
    # Codex reads [features] as a table of booleans (a few features take a table);
    # anything else there fails the whole load.
    if not isinstance(features, dict) or not all(isinstance(v, (bool, dict)) for v in features.values()):
        return True
    return any(k in features and features[k] is not True for k in ("hooks", "codex_hooks"))


def _codex_hook_registered(hooks_path: Path, wrapper: Path) -> bool:
    """Whether this hooks.json registers our wrapper for every event, read as the profile's user the way codex
    does (following a symlink). Anything codex couldn't load counts as not registered."""
    try:
        config = _load_codex_json(_read_user_file(hooks_path, follow=True))
        if not _codex_can_load(config):
            return False
    except Exception:  # RecursionError included: too deep for codex too
        return False
    events = config.get("hooks", {})
    # Every event setup installs, or a dropped PreToolUse would still read healthy.
    return all(any(_codex_group_runs_wrapper(group, wrapper, event)
                   for group in (events.get(event) if isinstance(events.get(event), list) else []))
               for event in _codex_hooks_config(None))


def _writable_dir(path: Path) -> bool:
    """Runs as the profile's user: setup could replace files in this folder."""
    return os.access(path, os.W_OK | os.X_OK)


def _codex_wrapper_present(wrapper: Path) -> bool:
    """A regular file at our path, not followed: a symlink there isn't something we installed."""
    try:
        return stat.S_ISREG(wrapper.lstat().st_mode)
    except OSError:
        return False


def _codex_wrapper_runnable(wrapper: Path) -> bool:
    """Runs as the profile's user: codex launches the path through the shell, which
    needs read and execute for that user."""
    return os.access(wrapper, os.R_OK | os.X_OK)


def _codex_detect_state(m, user_homes):
    """Our entry in codex's system hooks.json, and no profile turning codex hooks off. Before setup
    first writes that file, the per-user install it replaces is judged instead."""
    try:
        system = m.get_managed_settings_dir() / "hooks.json"
        if os.path.lexists(system) and str(HOOK_BINARY) in system.read_text(encoding="utf-8", errors="replace"):
            state = _detect_state(system, _codex_system_hooks_config())
            if state == "persisted":
                try:
                    loads = _codex_can_load(_load_codex_json(_read_user_file(system, follow=True)))
                except (OSError, ValueError, RecursionError):
                    loads = False
                if not loads:
                    return "tampered"  # codex refuses the whole file, our entries included
            for username, home_dir in user_homes if state == "persisted" else ():
                disabled = _as_user(m, username, _codex_hooks_disabled, home_dir / ".codex" / "config.toml")
                if disabled is None or disabled:
                    return "tampered"
            return state
        # Per profile, on the pair the user-level install wrote (wrapper script and hooks.json entry).
        any_complete = False
        for username, home_dir in user_homes:
            wrapper = home_dir / ".codex" / "hooks" / "unbound.py"
            hooks_path = home_dir / ".codex" / "hooks.json"
            script = _codex_wrapper_present(wrapper)
            if script:
                script = _as_user(m, username, _codex_wrapper_runnable, wrapper)
                if script is False:
                    return "tampered"  # our path holds a file this user can't run
            registered = False
            if os.path.lexists(hooks_path):
                registered = _as_user(m, username, _codex_hook_registered, hooks_path, wrapper)
            if registered is None or script is None:
                # Only reached for a profile holding our files: its user can kill or stop
                # the check, so a check that didn't answer doesn't keep the old state.
                return "tampered"
            elif script and registered:
                # Both halves in place, yet codex may still run nothing: the hooks feature
                # turned off, or a config.toml codex can't load.
                disabled = _as_user(m, username, _codex_hooks_disabled, hooks_path.parent / "config.toml")
                if disabled is None or disabled:
                    return "tampered"
                else:
                    any_complete = True
            elif script or registered:
                return "tampered"
        return "persisted" if any_complete else "fresh"
    except Exception as e:
        print(f"[setup] codex install_state detection failed: {e}", file=sys.stderr)
        return None


def _setup_cursor(opts):
    m = _module("cursor")
    base, gateway = _normalized_urls(m, opts)
    if opts["backfill"]:
        print("[backfill] Cursor backfill is not supported — no historical transcript data is available on disk.")
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")
    report = _tool_reporter(opts, m, "cursor", api_key, backend_url=base, serial_number=device_id,
                            installed=opts.get("installed", {}).get("cursor", True),
                            install_mode="binary")

    config_ok = True
    for username, home_dir in m.get_all_user_homes():
        if _write_user_config(m, opts, username, home_dir, api_key):
            m.remove_user_level_hooks(username, home_dir)
        else:
            config_ok = False
    m.remove_legacy_key_env()

    state = _detect_state(m.get_enterprise_hooks_dir() / "hooks.json", _cursor_hooks_json()["hooks"],
                          relative_ok=True)
    hooks_ok, hooks_changed = _write_cursor_enterprise_hooks(m)
    if not hooks_ok:
        return report("deferred", "enterprise hooks.json write failed")
    _remove_stale_managed_script(m.get_enterprise_hooks_dir())

    if not config_ok:
        return report("deferred", "config.json write failed for some users")

    outcome = report("configured", install_state=state, hook_hash=m.hook_script_hash(hook_source_path("cursor")),
                     written_to=str(m.get_enterprise_hooks_dir() / "hooks.json"))
    if hooks_changed:
        m.restart_cursor()
    return outcome


def _copilot_detect_state(m, user_homes):
    """Per profile, as that user: ~/.copilot/hooks/unbound.json must run our command on every event. 'tampered'
    if any doesn't or its check didn't answer, 'fresh' if none exists, else 'persisted'; None on failure."""
    try:
        any_complete = False
        for username, home_dir in user_homes:
            if home_dir is None:
                continue
            path = home_dir / ".copilot" / "hooks" / "unbound.json"
            if not os.path.lexists(path):
                continue
            # A check its user killed or stopped (None) doesn't keep the old state either.
            if not _as_user(m, username, _copilot_registered, path):
                return "tampered"
            any_complete = True
        return "persisted" if any_complete else "fresh"
    except Exception as e:
        print(f"[setup] copilot install_state detection failed: {e}", file=sys.stderr)
        return None


def _copilot_current(path: Path) -> bool:
    """Runs as the profile's user: the file holds this release's registration."""
    try:
        config = _strict_json(_read_user_file(path, follow=True).decode("utf-8"))
        hooks = config.get("hooks") if isinstance(config, dict) else None
        return _holds_every_entry(hooks, _copilot_hooks_config()["hooks"])
    except Exception:
        return False


def _copilot_registered(path: Path) -> bool:
    """Runs as the profile's user: every event still holds the entry setup wrote, or (a python-era install
    being migrated) runs its own still-present unbound.py in both command and bash."""
    try:
        config = _strict_json(_read_user_file(path, follow=True).decode("utf-8"))
        hooks = config.get("hooks") if isinstance(config, dict) else None
        expected = _copilot_hooks_config()["hooks"]
        script = path.parent / "unbound.py"
        quoted = f'"{script}"'
        return _holds_every_entry(hooks, expected) or (
            not any(ch in '$`\\"' for ch in str(script))  # double quotes still expand these
            and _codex_wrapper_present(script) and _codex_wrapper_runnable(script) and _runs_on_every_event(
                hooks, expected, lambda h: h.get("type") == "command"
                and h.get("command") == quoted and h.get("bash") == quoted, grouped=False))
    except Exception:  # RecursionError included: Copilot can't load it either
        return False


def _setup_copilot(opts):
    m = _module("copilot")
    m._RUN_AS_USER_TIMEOUT = _USER_CHECK_TIMEOUT  # until the report: a user can pause a call
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")
    report = _tool_reporter(opts, m, "copilot", api_key, backend_url=base, serial_number=device_id,
                            installed=opts.get("installed", {}).get("copilot", True),
                            install_mode="binary")

    user_homes = m.get_all_user_homes()
    state = _copilot_detect_state(m, user_homes)
    installed = 0
    config_ok = True
    for username, home_dir in user_homes:
        if home_dir is None:
            continue  # no home to hold a config or a registration
        config_ok = _write_user_config(m, opts, username, home_dir, api_key) and config_ok
        # Earlier versions configured the exporter here, per user, in VS Code
        # settings. The managed file written below outranks those, so they are only
        # taken back out.
        m.clear_otel_export_for_user(username, home_dir)
        registration = home_dir / ".copilot" / "hooks" / "unbound.json"
        had_registration = os.path.lexists(registration)  # a profile setup never reached isn't tampered
        if _install_copilot_hooks_for_user(m, username, home_dir):
            installed += 1
        elif state == "persisted" and had_registration and (
                _as_user(m, username, _copilot_registered, registration) is False
                # A folder locked against setup keeps whatever's there, which only
                # today's registration vouches for (a python-era script isn't checked).
                or (_as_user(m, username, _writable_dir, registration.parent) is False
                    and _as_user(m, username, _copilot_current, registration) is False)):
            state = "tampered"
    m.remove_legacy_key_env()

    # Machine-wide, so once for the device rather than once per user. Called
    # explicitly: this command drives the vendored module's named functions rather
    # than its main(), so a writer added there is dead code here until it is invoked.
    m.configure_managed_telemetry(api_key, gateway_url=gateway)

    if user_homes and installed == 0:
        # A user can make every install fail, so the report carries the state found: the backend counts a
        # tamper on a deferred report without marking the tool connected or deployed.
        return report("deferred", "hook install failed for all users", install_state=state)

    if not config_ok:
        return report("deferred", "config.json write failed for some users")

    # One file per user, so the per-user path rather than any one home's.
    outcome = report("configured", install_state=state, hook_hash=m.hook_script_hash(hook_source_path("copilot")),
                     written_to="~/.copilot/hooks/unbound.json")
    if opts["backfill"]:
        hook_source = hook_source_path("copilot").read_text(encoding="utf-8")
        m._RUN_AS_USER_TIMEOUT = None  # a backfill takes as long as it takes
        m.run_backfill(api_key, base, user_homes, hook_source)
    return outcome


def _fetch_device_owner_key(opts):
    """Resolve the API key of the user this device belongs to, from its hardware
    serial. Replaces the org discovery key: the scan authenticates as the owner,
    so the device is attributed to them. Returns None when it can't be resolved."""
    m = _module("claude-code")
    device_id = m.get_device_identifier()
    if not device_id:
        return None
    return m.fetch_api_key_from_mdm(
        opts["backend_url"], opts["app_name"], opts["api_key"], device_id,
        app_type="default",
    )


SCAN_SKIPPED_PREFIX = "Scan skipped:"


def _echo_scan_output(stream, skipped) -> None:
    """Pass the scan's stdout through to the MDM log line by line, keeping the reason
    of the first 'Scan skipped: <reason>' line it prints. A log that can't be written stops the
    echo, never the reading: a full pipe would stall the scan until the backstop."""
    echo = True
    try:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", "replace")
            if echo:
                try:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                except Exception:
                    echo = False
            if not skipped and line.startswith(SCAN_SKIPPED_PREFIX):
                skipped.append(line[len(SCAN_SKIPPED_PREFIX):].strip())
    except Exception:
        pass


def _run_discovery(opts):
    """Run the locally installed discovery binary (no install.sh download).
    Mirrors onboard.py's process-group + backstop-kill discipline."""
    if not DISCOVERY_BINARY.is_file():
        return ("deferred", f"discovery binary not installed at {DISCOVERY_BINARY}")
    scan_key = _fetch_device_owner_key(opts)
    if not scan_key:
        return ("skipped", "could not resolve the device owner's key from the serial")
    # Key via env, never argv — the scan runs up to 90 min and argv is
    # visible to every local user via ps (same contract the hook modules'
    # frozen discovery dispatch uses).
    cmd = [str(DISCOVERY_BINARY), "--domain", opts["backend_url"]]
    env = {**os.environ, "UNBOUND_API_KEY": scan_key}
    backstop = DISCOVERY_TIMEOUT_SECONDS + DISCOVERY_KILL_GRACE_SECONDS
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, env=env, stdout=subprocess.PIPE)
        skipped = []
        echo = threading.Thread(target=_echo_scan_output, args=(proc.stdout, skipped), daemon=True)
        echo.start()
        try:
            rc = proc.wait(timeout=backstop)
            echo.join(timeout=5)  # a child still holding the pipe must not hold setup
        except subprocess.TimeoutExpired:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=15)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
            return ("deferred", f"discovery exceeded {backstop}s and was terminated")
        if skipped:  # it ran and chose not to scan: nothing for a re-run to retry
            return ("skipped", skipped[0] or "scan skipped")
        if rc != 0:
            return ("deferred", f"discovery exited with code {rc}")
        return ("configured", None)
    except Exception as e:
        return ("deferred", f"discovery launch failed: {e}")


_ADAPTERS = {
    "claude-code": _setup_claude_code,
    "cursor": _setup_cursor,
    "codex": _setup_codex,
    "copilot": _setup_copilot,
    "augment": _setup_augment,
}


def run(argv) -> int:
    opts = _parse_args(argv)
    if opts is None:
        return 2
    if not opts["api_key"]:
        print("Error: --api-key is required (the MDM admin key).", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    try:
        m0 = load_mdm_setup_module("claude-code")
        admin = m0.check_admin_privileges()
    except Exception:
        admin = False
    if not admin:
        print("unbound-hook setup requires administrator/root privileges. Re-run with sudo.",
              file=sys.stderr)
        return 1

    # Normalize once at the boundary so every consumer (adapters, discovery
    # --domain) sees a schemed, trailing-slash-free URL.
    opts["backend_url"] = m0.normalize_url(opts["backend_url"])
    opts["gateway_url"] = m0.normalize_url(opts["gateway_url"])
    # Optional: only when given, so an absent value stays None and the config
    # writer keeps skipping it.
    if opts["frontend_url"]:
        opts["frontend_url"] = m0.normalize_url(opts["frontend_url"])

    opts["config_writes"] = {}
    # Report-only inputs: none of them may stop the install or change its exit code.
    serial = _report_input(m0.get_device_identifier, None, "device serial")
    user_homes = _report_input(m0.get_all_user_homes, None, "user homes")
    warnings = _report_input(lambda: _preflight_warnings(user_homes), [], "preflight checks")
    # Once, before any tool writes: unknown homes (or a failed check) leave every tool reported as installed.
    opts["installed"] = _report_input(lambda: {} if user_homes is None else {
        tool: _tool_installed(tool, user_homes) for tool in opts["tools"] if tool in _TOOL_TYPES},
        {}, "installed tools")
    _send_run_report(opts, serial, "start", _start_fields)
    # Before the sweep: it removes ~/.cursor/hooks, and with it Cursor's error.log.
    home_keys = {}
    for tool in opts["tools"]:
        if tool in _HOOK_ERROR_LOGS:
            _forward_hook_errors(m0, tool, opts, user_homes, home_keys)

    statuses = {}

    print(f"\n{'=' * 60}\n[migration] python->binary sweep\n{'=' * 60}")
    # The sweep and Cursor's step remove ~/.cursor/hooks: a log the gateway has not taken is put back after.
    kept = [(u, log, _as_user(m0, u, _set_aside_unsent_log, log)) for u, log in opts.get("unsent_hook_logs", [])]
    # One the user can't move (they may not be able to write ~/.cursor) stays where it is: Cursor's
    # cleanup, which removes ~/.cursor/hooks as root, keeps it.
    cursor_hooks = load_mdm_setup_module("cursor").KEEP_UNSENT_HOOK_LOGS if kept else set()
    cursor_hooks.update(log for _, log, data in kept if not data and os.path.lexists(log))
    statuses["migration"] = migration.run_sweep(tools=opts["tools"])

    for tool in opts["tools"]:
        adapter = _ADAPTERS.get(tool)
        if adapter is None:
            statuses[tool] = ("skipped", f"unknown tool {tool!r}")
            continue
        print(f"\n{'=' * 60}\n[{tool}] MDM setup\n{'=' * 60}")
        try:
            statuses[tool] = adapter(opts)
        except SystemExit as e:
            statuses[tool] = _report_failed_setup(opts, tool, f"component exited early: {e}")
        except Exception as e:
            statuses[tool] = _report_failed_setup(opts, tool, f"error: {e}")

    cursor_hooks.clear()
    for username, log, data in kept:
        if data and _as_user(m0, username, _restore_unsent_log, log, data) is not True and not os.path.lexists(log):
            print(f"[errors] {log}: unsent hook errors could not be kept for the next run")

    print(f"\n{'=' * 60}\n[discovery] coding-tool scan\n{'=' * 60}")
    try:
        statuses["discovery"] = _run_discovery(opts)
    except Exception as e:
        statuses["discovery"] = ("deferred", f"error: {e}")

    print(f"\n{'=' * 60}\nunbound-hook setup summary\n{'=' * 60}")
    any_deferred = False
    for component, (status, reason) in statuses.items():
        line = f"  {component:12s} {status}"
        if reason:
            line += f" ({reason})"
        print(line)
        if status == "deferred":
            any_deferred = True
    _send_run_report(opts, serial, "end", lambda: _end_fields(opts, user_homes, warnings))
    return 1 if any_deferred else 0
