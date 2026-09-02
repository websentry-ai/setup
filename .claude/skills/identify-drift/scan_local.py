#!/usr/bin/env python3
"""Read what each tool recorded locally, and what our hook saw, for one time window.

Two local sources, deliberately kept apart:

  transcript  what the editor itself wrote. The ground truth for what the user did.
  audit       what our hook observed and logged. What we had a chance to upload.

Keeping them apart is what localises a loss. Present in the transcript but absent
from the audit log means the hook never saw it. Present in the audit log but absent
from the database means the upload lost it. Collapsing the two would only say
"something is missing".

Emits one JSON document on stdout; compare.py consumes it.
"""

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOME = Path.home()

# app_label is the value the hook stamps on every payload, and the value the
# database stores, so it is the join key between the two sides.
# The hook keeps only this many audit entries in total, across every event type.
# At the cap the log has rotated, and absence from it proves nothing.
AUDIT_LOG_TOTAL_LIMIT = 100

# The widest window either half of the skill will look at.
MAX_DAYS = 14

TOOLS = {
    "claude-code": {"app_label": "claude-code", "audit": HOME / ".claude/hooks/agent-audit.log"},
    "cursor":      {"app_label": "cursor",      "audit": HOME / ".cursor/hooks/agent-audit.log"},
    "copilot":     {"app_label": "copilot",     "audit": HOME / ".copilot/hooks/agent-audit.log"},
    "codex":       {"app_label": "codex",       "audit": HOME / ".codex/hooks/agent-audit.log"},
    "augment":     {"app_label": "augment_code","audit": HOME / ".augment/hooks/agent-audit.log"},
}


def _ts(value):
    """Parse the several timestamp spellings these files use, or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # milliseconds if it is far too large to be seconds
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _lines(path):
    """JSONL, tolerant: a half-written last line is normal on a live session.

    Only regular files. Reading a pipe left in a transcript directory would wait for
    a writer that never comes, and the scan would hang rather than finish. Checked on
    the descriptor so the answer cannot change after the look.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return
    except OSError:
        os.close(fd)
        return
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def _blocks(content):
    """Anthropic-shaped content: a string, or a list of typed blocks."""
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


_TEXT_BLOCKS = ("text", "input_text", "output_text")


def _text_of(content):
    return "\n".join(b.get("text", "") for b in _blocks(content)
                     if b.get("type") in _TEXT_BLOCKS).strip()


def _rec(kind, session, when, **extra):
    item = {"kind": kind, "session": session,
            "at": when.isoformat() if when else None}
    item.update(extra)
    return item


# ---------------------------------------------------------------- transcripts

def _file_time(path):
    """When a record carries no time of its own, the file's is the closest thing.
    Without it an undated record is never filtered, so a transcript from months ago
    is compared against a fourteen-day window and every prompt in it reads as lost.
    Cursor writes no per-record timestamp at all."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def _is_submission(prompt_source, tagged):
    """A user record is a prompt only if the person sent it. The rest of what lands
    under the user role -- injected reminders, slash-command expansions, command
    output, task notifications -- was never submitted, so the hook never saw it and
    counting it as absent from the database invents losses by the dozen. Newer
    transcripts mark every real submission; older ones mark nothing, and filtering on
    a field a file never writes would drop every prompt in it and read as total loss,
    so the mark is only trusted in a file that uses it."""
    return prompt_source in ("typed", "queued") if tagged else True


def scan_claude_code(since):
    for path in (HOME / ".claude/projects").glob("*/*.jsonl"):
        session = path.stem
        # Held back until the file has been read: whether it marks its submissions is
        # only known once every record has been seen, and a file is read once.
        prompts, tagged = [], False
        for entry in _lines(path):
            if entry.get("type") == "user" and entry.get("promptSource"):
                tagged = True
            when = _ts(entry.get("timestamp")) or _file_time(path)
            if not when or when < since:
                continue
            kind = entry.get("type")
            message = entry.get("message") or {}
            if kind == "user":
                text = _text_of(message.get("content"))
                if text and not entry.get("isMeta"):
                    prompts.append((when, text, entry.get("promptSource")))
            elif kind == "assistant":
                text = _text_of(message.get("content"))
                if text:
                    yield _rec("assistant_message", session, when, text=text)
                for block in _blocks(message.get("content")):
                    if block.get("type") == "tool_use":
                        yield _rec("tool_call", session, when,
                                   tool=block.get("name"), call_id=block.get("id"))
                usage = message.get("usage") or {}
                if usage:
                    yield _rec("usage", session, when,
                               message_id=message.get("id"),
                               input=usage.get("input_tokens", 0),
                               output=usage.get("output_tokens", 0),
                               cache_read=usage.get("cache_read_input_tokens", 0),
                               cache_write=usage.get("cache_creation_input_tokens", 0))
        for when, text, prompt_source in prompts:
            if _is_submission(prompt_source, tagged):
                yield _rec("user_prompt", session, when, text=text)


def scan_cursor(since):
    for path in (HOME / ".cursor/projects").glob("*/agent-transcripts/*/*.jsonl"):
        session = path.stem
        for entry in _lines(path):
            when = _ts(entry.get("timestamp") or entry.get("createdAt")) or _file_time(path)
            if not when or when < since:
                continue
            role = entry.get("role")
            content = (entry.get("message") or {}).get("content")
            if role == "user":
                text = _text_of(content)
                if text:
                    yield _rec("user_prompt", session, when, text=text)
            elif role == "assistant":
                text = _text_of(content)
                if text:
                    yield _rec("assistant_message", session, when, text=text)
                for block in _blocks(content):
                    if block.get("type") in ("tool_use", "toolUse"):
                        yield _rec("tool_call", session, when,
                                   tool=block.get("name"), call_id=block.get("id"))


def _scan_copilot_file(path, session, since):
    for entry in _lines(path):
        data = entry.get("data") or {}
        when = _ts(entry.get("timestamp") or data.get("timestamp")) or _file_time(path)
        if not when or when < since:
            continue
        kind = entry.get("type")
        if kind == "user.message":
            text = (data.get("content") or "").strip()
            if text:
                yield _rec("user_prompt", session, when, text=text)
        elif kind == "assistant.message":
            text = (data.get("content") or "").strip()
            if text:
                yield _rec("assistant_message", session, when, text=text)
        elif kind == "tool.execution_start":
            yield _rec("tool_call", session, when,
                       tool=data.get("toolName"), call_id=data.get("toolCallId"))


def scan_copilot(since):
    for path in (HOME / ".copilot/session-state").glob("*/events.jsonl"):
        yield from _scan_copilot_file(path, path.parent.name, since)
    # The VS Code extension writes the same records under workspace storage.
    vscode = HOME / "Library/Application Support/Code/User/workspaceStorage"
    for path in vscode.glob("*/GitHub.copilot-chat/transcripts/*.jsonl"):
        yield from _scan_copilot_file(path, path.stem, since)


def scan_codex(since):
    for path in (HOME / ".codex/sessions").glob("*/*/*/rollout-*.jsonl"):
        session = None
        for entry in _lines(path):
            payload = entry.get("payload") or {}
            when = _ts(entry.get("timestamp") or payload.get("started_at")) or _file_time(path)
            if entry.get("type") == "session_meta":
                session = payload.get("id") or path.stem
            if not when or when < since:
                continue
            session = session or path.stem
            kind = payload.get("type")
            if entry.get("type") == "response_item" and kind == "message":
                text = _text_of(payload.get("content"))
                if not text:
                    continue
                role = payload.get("role")
                # "developer" carries injected instructions, not something the user typed.
                if role == "user":
                    yield _rec("user_prompt", session, when, text=text)
                elif role == "assistant":
                    yield _rec("assistant_message", session, when, text=text)
            elif entry.get("type") == "response_item" and kind == "function_call":
                yield _rec("tool_call", session, when,
                           tool=payload.get("name"), call_id=payload.get("call_id"))
            elif kind == "token_count":
                total = (payload.get("info") or {}).get("total_token_usage") or {}
                if total:
                    # Codex reports a running total per turn, not a per-message delta.
                    yield _rec("usage_total", session, when,
                               input=total.get("input_tokens", 0),
                               output=total.get("output_tokens", 0),
                               cache_read=total.get("cached_input_tokens", 0),
                               cache_write=total.get("cache_write_input_tokens", 0))


def scan_augment(since):
    """Augment keeps no rich transcript; the hook's audit log is the only local record."""
    return iter(())


SCANNERS = {
    "claude-code": scan_claude_code,
    "cursor": scan_cursor,
    "copilot": scan_copilot,
    "codex": scan_codex,
    "augment": scan_augment,
}


# ---------------------------------------------------------------- audit logs

def scan_audit(tool, since):
    path = TOOLS[tool]["audit"]
    for entry in _lines(path):
        when = _ts(entry.get("timestamp"))
        if not when or when < since:
            continue
        event = entry.get("event") or {}
        session = entry.get("session_id") or event.get("session_id")
        name = event.get("hook_event_name")
        if name in ("PreToolUse", "PostToolUse"):
            yield _rec("tool_call", session, when,
                       tool=event.get("tool_name"), call_id=event.get("tool_use_id"))
        elif name in ("UserPromptSubmit", "beforeSubmitPrompt"):
            text = (event.get("prompt") or "").strip()
            if text:
                yield _rec("user_prompt", session, when, text=text)
        elif name in ("Stop", "stop"):
            yield _rec("turn_end", session, when)


def _count_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", required=True, help="comma separated: %s" % ",".join(TOOLS))
    ap.add_argument("--days", type=int, required=True)
    ap.add_argument("--out", help="write here with owner-only permissions instead of "
                                  "stdout; the output quotes transcripts verbatim")
    args = ap.parse_args()

    if not 1 <= args.days <= MAX_DAYS:
        sys.exit("--days must be between 1 and %d" % MAX_DAYS)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in TOOLS]
    if unknown:
        sys.exit("unknown tool(s): %s" % ", ".join(unknown))

    since = datetime.now(timezone.utc) - timedelta(days=args.days)
    out = {"since": since.isoformat(), "days": args.days, "tools": {}}
    for tool in tools:
        transcript = list(SCANNERS[tool](since))
        audit = list(scan_audit(tool, since))
        audit_times = sorted(r["at"] for r in audit if r["at"])
        out["tools"][tool] = {
            "app_label": TOOLS[tool]["app_label"],
            "audit_log": str(TOOLS[tool]["audit"]),
            "audit_log_present": TOOLS[tool]["audit"].exists(),
            # The hook keeps only the last AUDIT_LOG_TOTAL_LIMIT entries, so anything
            # older than this has aged out rather than gone missing.
            "audit_window_start": audit_times[0] if audit_times else None,
            "audit_window_end": audit_times[-1] if audit_times else None,
            "audit_entries": _count_lines(TOOLS[tool]["audit"]),
            "audit_limit": AUDIT_LOG_TOTAL_LIMIT,
            "transcript": transcript,
            "audit": audit,
            "sessions_transcript": sorted({r["session"] for r in transcript if r["session"]}),
            "sessions_audit": sorted({r["session"] for r in audit if r["session"]}),
        }
    if args.out:
        # Every prompt and reply the window covers ends up in here. A shell redirect
        # would create it with the default umask, which on a shared machine is
        # world-readable, so the file is opened with owner-only permissions instead.
        # O_NOFOLLOW: a symlink planted here would redirect the truncate onto whatever
        # it points at. O_NONBLOCK: opening a pipe for writing otherwise waits for a
        # reader, so a planted one would hang the scan instead of failing it.
        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
                 | os.O_NONBLOCK)
        try:
            fd = os.open(args.out, flags, 0o600)
        except OSError as error:
            sys.exit("cannot write %s: %s" % (args.out, error.strerror))
        # Checked on the descriptor, not the path, so nothing can be swapped in
        # between. A pipe left here by another account would carry every prompt in the
        # window straight to whoever is reading it, and permissions do not stop that.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            sys.exit("%s is not a regular file; refusing to write the scan into it"
                     % args.out)
        # The mode argument only applies when the file is created, so an existing
        # destination would keep whatever permissions it already had.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(out, handle, indent=2)
    else:
        json.dump(out, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
