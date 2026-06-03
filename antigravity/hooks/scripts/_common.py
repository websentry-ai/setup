#!/usr/bin/env python3
"""Shared helpers for Antigravity hook scripts.

All four installed hook scripts (`unbound_pre_tool_use.py`,
`unbound_post_tool_use.py`, `unbound_user_prompt_submit.py`,
`unbound_session_start.py`) are deployed side-by-side into
``~/.antigravity/hooks/`` by ``setup.py`` and import this file via a
``sys.path`` insert at the top of each script.

The Antigravity wire format (verified against ``AgusRdz/chop``):

- Stdin: snake_case
  ``{"session_id","cwd","hook_event_name","tool_name","tool_input"}``
- Stdout (only when overriding the default allow): camelCase
  ``{"hookSpecificOutput": {"hookEventName", "permissionDecision",
                            "updatedInput"?}}``
- Tool names arrive as either ``"bash"`` or ``"Bash"`` for the same
  logical tool — handle case-insensitively when matching.
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
    """Read the Antigravity hook payload from stdin. Returns None on any error."""
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


def normalize_tool_name(tool_name: str) -> str:
    """Antigravity emits both ``bash`` and ``Bash``; canonicalise to title-case
    for matching against our APP_NATIVE_FILE_TOOLS mapping server-side."""
    if not tool_name:
        return ""
    lower = tool_name.lower()
    if lower == "bash":
        return "Bash"
    if lower == "websearch":
        return "WebSearch"
    if lower == "webfetch":
        return "WebFetch"
    # Title-case for common single-word tool names; passthrough for the rest.
    return tool_name


def extract_command_for_pretool(event: Dict[str, Any]) -> str:
    """Mirror ``codex/hooks/unbound.py::extract_command_for_pretool``.

    Returns the most-meaningful identifier for the tool invocation —
    the command/path/pattern/query/prompt depending on tool_name.
    """
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return event.get("tool_name", "") or ""

    tool_name = normalize_tool_name(event.get("tool_name", "") or "")

    if tool_name == "Bash" and "command" in tool_input:
        return tool_input["command"] or ""
    if tool_name in ("Write", "Edit", "Read") and "file_path" in tool_input:
        return tool_input["file_path"] or ""
    if tool_name == "Grep" and "pattern" in tool_input:
        return tool_input["pattern"] or ""
    if tool_name == "Glob" and "pattern" in tool_input:
        return tool_input["pattern"] or ""
    if tool_name == "WebFetch" and "url" in tool_input:
        return tool_input["url"] or ""
    if tool_name == "WebSearch" and "query" in tool_input:
        return tool_input["query"] or ""
    if tool_name == "Task" and "prompt" in tool_input:
        return tool_input["prompt"] or ""
    return tool_name


def build_request_body(event: Dict[str, Any]) -> Dict[str, Any]:
    """Shape the gateway request body to match ``PretoolRequestBody`` in
    ``ai-gateway/src/handlers/preToolUseHandler.ts:86-100``."""
    tool_name = normalize_tool_name(event.get("tool_name", "") or "")
    command = extract_command_for_pretool(event)
    tool_input = event.get("tool_input") or {}

    metadata: Dict[str, Any] = {"hook_event_name": event.get("hook_event_name") or ""}
    if event.get("cwd"):
        metadata["cwd"] = event["cwd"]
    if isinstance(tool_input, dict):
        metadata["tool_input"] = tool_input

    return {
        "conversation_id": event.get("session_id") or "",
        "event_name": event.get("hook_event_name") or "",
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


def emit_hook_output(event_name: str, decision: str, reason: str = "") -> None:
    """Write the Antigravity stdout payload. Lowercase ``decision``,
    PascalCase ``event_name``. Only call this when overriding the default
    allow — silent (no stdout) is the canonical allow."""
    decision = (decision or "").lower()
    if decision not in ("allow", "deny", "ask"):
        return
    payload: Dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": decision,
        }
    }
    if reason:
        payload["hookSpecificOutput"]["permissionDecisionReason"] = reason
    sys.stdout.write(json.dumps(payload))


def fire_and_forget_telemetry(event: Dict[str, Any]) -> None:
    """Post-tool-use / user-prompt-submit / session-start telemetry. Best-effort,
    fail-open, exits 0 silently. Used by the three non-decision hook scripts."""
    creds = load_credentials()
    if not creds["api_key"]:
        return
    body = build_request_body(event)
    # Telemetry endpoints don't gate the agent — we don't even need the response.
    post_to_gateway(body, creds["api_key"], creds["gateway_url"])
