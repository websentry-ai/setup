#!/usr/bin/env python3
"""Antigravity PreToolUse hook.

Reads the snake_case stdin payload, POSTs to ``${gateway}/hooks/antigravity``,
and emits a camelCase ``hookSpecificOutput`` whose ``permissionDecision``
mirrors the gateway response. Fail-open: any infra error means silent allow.
"""

import os
import sys

# When installed to ~/.antigravity/hooks/unbound_pre_tool_use.py, _common.py
# sits beside it; make sure we can import either way.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import (  # noqa: E402
    build_request_body,
    emit_hook_output,
    load_credentials,
    post_to_gateway,
    read_stdin_event,
)


def main() -> int:
    event = read_stdin_event()
    if event is None:
        return 0  # malformed input → fail-open silent allow

    event_name = event.get("hook_event_name") or "PreToolUse"

    creds = load_credentials()
    if not creds["api_key"]:
        return 0  # not configured → fail-open

    body = build_request_body(event)
    api_response = post_to_gateway(body, creds["api_key"], creds["gateway_url"])
    if not api_response:
        return 0  # gateway unreachable / non-2xx → fail-open

    decision = (api_response.get("decision") or "allow").lower()
    if decision == "allow":
        return 0  # silent allow

    reason = api_response.get("reason") or ""
    emit_hook_output(event_name, decision, reason=reason)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Iron law: never block the agent on our infra. Any unhandled error
        # at this layer is a bug in our hook script, not a user-visible event.
        sys.exit(0)
