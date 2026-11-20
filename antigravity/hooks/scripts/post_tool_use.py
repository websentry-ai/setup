#!/usr/bin/env python3
"""Antigravity PostToolUse telemetry hook. Fire-and-forget; never blocks.

agy fires PostToolUse on every step including non-tool turns, where
``toolCall`` is ``null``. We skip the gateway POST in that case — no tool
identity means no policy-relevant telemetry to record.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import fire_and_forget_telemetry, read_stdin_event  # noqa: E402

try:
    event = read_stdin_event()
    if event is not None and isinstance(event.get("toolCall"), dict):
        fire_and_forget_telemetry(event, "PostToolUse")
except Exception:
    pass
sys.exit(0)
