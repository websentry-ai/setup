#!/usr/bin/env python3
"""Antigravity UserPromptSubmit telemetry hook.

Telemetry only. Posts the prompt event to ``${gateway}/hooks/antigravity``
and exits 0 silently. Never blocks the agent.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import fire_and_forget_telemetry, read_stdin_event  # noqa: E402


def main() -> int:
    event = read_stdin_event()
    if event is None:
        return 0
    fire_and_forget_telemetry(event)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
