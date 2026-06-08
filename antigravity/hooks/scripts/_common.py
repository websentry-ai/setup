#!/usr/bin/env python3
"""Shared helpers for Antigravity hook scripts.

Both installed hook scripts (`unbound_pre_tool_use.py`,
`unbound_post_tool_use.py`) are deployed side-by-side into
``~/.unbound/antigravity-hooks/`` by ``setup.py`` and import this file
via a ``sys.path`` insert at the top of each script.

The Antigravity (agy 1.0.5) wire format, verified empirically (see
``AGY-EMPIRICAL-FINDINGS.md``):

- Stdin: camelCase
  ``{"artifactDirectoryPath","conversationId","stepIdx",
     "toolCall":{"name","args":{<PascalCase keys>}},
     "transcriptPath","workspacePaths":[...],
     "error":""}``  (``error`` and ``toolCall: null`` are PostToolUse-only)
- Env: ``ANTIGRAVITY_CONVERSATION_ID`` mirrors ``conversationId``.
- Stdout (only when overriding the default allow): bare native-proto
  ``{"decision": "allow"|"deny"|"ask", "reason": "<surfaced to model>"}``.
  No ``hookSpecificOutput`` wrapper — chop's shape is wrong for agy.
- Tool names are agy-native and lowercase (``run_command``, ``view_file``,
  ``edit_file``, ``write_to_file``, ``codebase_search``, ``ask_permission``).
  No ``bash`` / ``Bash`` duality.
- Fail-open on any infra error (timeout, non-2xx, JSON parse): print
  nothing, exit 0. Never block the agent on our infra.
"""

import http.client
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


UNBOUND_APP_LABEL = "antigravity"
GATEWAY_HOOK_PATH = "/hooks/antigravity"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
GATEWAY_TIMEOUT_SECONDS = 3

UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"


def read_stdin_event() -> Optional[Dict[str, Any]]:
    """Read the agy hook payload from stdin. Returns None on any error."""
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    if not raw:
        return None
    try:
        event = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return event if isinstance(event, dict) else None


def load_credentials() -> Dict[str, str]:
    """Resolve api_key and gateway_url. Env vars override ``~/.unbound/config.json``.

    Returns a dict with possibly-empty string values; never raises.
    """
    api_key = os.environ.get("UNBOUND_API_KEY", "") or ""
    gateway_url = os.environ.get("UNBOUND_GATEWAY_URL", "") or ""

    if not api_key or not gateway_url:
        try:
            if UNBOUND_CONFIG_PATH.exists():
                with open(UNBOUND_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.loads(f.read())
                if isinstance(config, dict):
                    if not api_key:
                        api_key = (config.get("api_key") or "").strip()
                    if not gateway_url:
                        gateway_url = (config.get("gateway_url") or "").strip()
        except (OSError, ValueError):
            pass

    if not gateway_url:
        gateway_url = DEFAULT_GATEWAY_URL

    return {"api_key": api_key, "gateway_url": gateway_url.rstrip("/")}


def _coerce_str(value: Any) -> str:
    """Stringify a value for the gateway's ``command`` field; never raise."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _extract_command_and_metadata(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Map agy's per-tool PascalCase args onto the gateway's ``command`` +
    ``metadata`` shape. Unknown tools fall through to a JSON-stringified
    args blob so we never crash on a tool we haven't taught the map yet."""
    if not isinstance(args, dict):
        args = {}

    if tool_name == "run_command":
        command = _coerce_str(args.get("CommandLine"))
        metadata: Dict[str, Any] = {}
        if args.get("Cwd"):
            metadata["cwd"] = args["Cwd"]
        return {"command": command, "metadata": metadata}

    if tool_name == "view_file":
        path = _coerce_str(args.get("AbsolutePath"))
        return {"command": path, "metadata": {"file_path": path}}

    if tool_name == "edit_file":
        target = _coerce_str(args.get("TargetFile"))
        metadata = {"file_path": target}
        if args.get("CodeMarkdownLanguage"):
            metadata["code_markdown_language"] = args["CodeMarkdownLanguage"]
        return {
            "command": _coerce_str(args.get("Instruction")),
            "metadata": metadata,
        }

    if tool_name == "write_to_file":
        target = _coerce_str(args.get("TargetFile"))
        return {"command": "", "metadata": {"file_path": target}}

    if tool_name == "codebase_search":
        query = _coerce_str(args.get("Query"))
        metadata = {}
        if args.get("TargetDirectories") is not None:
            metadata["target_directories"] = args["TargetDirectories"]
        return {"command": query, "metadata": metadata}

    if tool_name == "ask_permission":
        action = _coerce_str(args.get("Action"))
        target = _coerce_str(args.get("Target"))
        reason = _coerce_str(args.get("Reason"))
        return {
            "command": f"{action}: {target}".strip(": "),
            "metadata": {"action": action, "target": target, "reason": reason},
        }

    # Fallback: stringify args opaquely so unknown tools don't crash.
    return {"command": _coerce_str(args), "metadata": {"args": args}}


def build_request_body(event: Dict[str, Any], event_name: str) -> Dict[str, Any]:
    """Shape the gateway request body to match ``PretoolRequestBody`` in
    ``ai-gateway/src/handlers/preToolUseHandler.ts:86-100``.

    ``event_name`` is the script's identity (PreToolUse vs PostToolUse) —
    agy's stdin payload has no ``hook_event_name`` field, so each script
    knows its own event from its filename.
    """
    tool_call = event.get("toolCall") if isinstance(event, dict) else None
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("name") or ""
        tool_args = tool_call.get("args") or {}
    else:
        tool_name = ""
        tool_args = {}

    mapped = _extract_command_and_metadata(tool_name, tool_args if isinstance(tool_args, dict) else {})
    command = mapped["command"]
    metadata: Dict[str, Any] = mapped["metadata"] or {}

    # Always tag the metadata with the hook event and a workspace hint if we
    # have one — these are the two breadcrumbs the gateway uses for policy
    # context that aren't already in the per-tool field map.
    metadata["hook_event_name"] = event_name
    workspaces = event.get("workspacePaths") if isinstance(event, dict) else None
    if isinstance(workspaces, list) and workspaces:
        first = workspaces[0]
        if isinstance(first, str) and first:
            metadata.setdefault("cwd", first)
            metadata["workspace"] = first
    if isinstance(event, dict) and event.get("stepIdx") is not None:
        metadata["step_idx"] = event["stepIdx"]
    if isinstance(event, dict) and event.get("error"):
        metadata["error"] = event["error"]

    conversation_id = ""
    if isinstance(event, dict):
        conversation_id = event.get("conversationId") or ""
    if not conversation_id:
        conversation_id = os.environ.get("ANTIGRAVITY_CONVERSATION_ID", "") or ""

    # ``event_name: 'tool_use'`` matches claude-code/hooks/unbound.py — the
    # gateway treats tool events under a single key regardless of which
    # pre/post phase fired, the actual phase is in metadata.hook_event_name.
    return {
        "conversation_id": conversation_id,
        "event_name": "tool_use",
        "unbound_app_label": UNBOUND_APP_LABEL,
        "model": "auto",
        "pre_tool_use_data": {
            "tool_name": tool_name,
            "command": command,
            "metadata": metadata,
        },
        "messages": [],
        "user_prompts": [],
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block redirects: returning None from ``redirect_request`` makes urllib
    surface 3xx as an HTTPError instead of silently following the Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def post_to_gateway(
    body: Dict[str, Any],
    api_key: str,
    gateway_url: str,
    timeout: int = GATEWAY_TIMEOUT_SECONDS,
) -> Optional[Dict[str, Any]]:
    """POST to ${gateway_url}/hooks/antigravity. Returns parsed JSON dict on
    HTTP 2xx with a JSON body, otherwise None. Fail-open by contract: any
    exception, timeout, non-2xx, or non-JSON body returns None.

    Uses urllib (not curl) so the Authorization header never appears on argv
    — curl's argv is world-readable via ``ps auxe`` / ``/proc/<pid>/cmdline``
    and would leak the bearer token to any local user. Redirects are blocked
    via a custom opener: the gateway is a single hop, so following 3xx would
    mask misconfig (unintended HTTP→HTTPS, proxy rewrite) instead of
    surfacing it as a hard failure we can debug.
    """
    if not api_key or not gateway_url:
        return None
    url = f"{gateway_url}{GATEWAY_HOOK_PATH}"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
            if not (200 <= resp.status < 300):
                return None
            raw = resp.read()
    except (urllib.error.URLError, http.client.HTTPException, OSError,
            socket.timeout, ValueError, UnicodeDecodeError):
        return None

    if not raw:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def emit_hook_output(decision: str, reason: str = "") -> None:
    """Write the agy stdout payload. Bare native-proto shape:
    ``{"decision": "...", "reason": "..."}``. No wrapper. Only call this
    when overriding the default allow — empty stdout + exit 0 is the
    canonical allow."""
    decision = (decision or "").lower()
    if decision not in ("allow", "deny", "ask"):
        return
    payload: Dict[str, Any] = {"decision": decision}
    if reason:
        payload["reason"] = reason
    sys.stdout.write(json.dumps(payload))


def fire_and_forget_telemetry(event: Dict[str, Any], event_name: str) -> None:
    """Post-tool-use telemetry. Best-effort, fail-open, exits 0 silently.

    For PostToolUse with ``toolCall: null`` (non-tool turns — agy fires this
    on every step), the caller should skip this entirely; we don't have
    enough context to make a useful telemetry record.
    """
    creds = load_credentials()
    if not creds["api_key"]:
        return
    body = build_request_body(event, event_name)
    # Telemetry endpoints don't gate the agent — we don't even need the response.
    post_to_gateway(body, creds["api_key"], creds["gateway_url"])
