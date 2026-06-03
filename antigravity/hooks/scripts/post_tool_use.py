#!/usr/bin/env python3
"""Antigravity PostToolUse telemetry hook. Fire-and-forget; never blocks."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import fire_and_forget_telemetry, read_stdin_event  # noqa: E402

try:
    event = read_stdin_event()
    if event is not None:
        fire_and_forget_telemetry(event)
except Exception:
    pass
sys.exit(0)
