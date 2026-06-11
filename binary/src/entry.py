#!/usr/bin/env python3
"""PyInstaller entry script for the unbound-hook binary.

Also usable directly in a repo checkout:
    python3 binary/src/entry.py hook claude-code PreToolUse < event.json
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unbound_hook.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
