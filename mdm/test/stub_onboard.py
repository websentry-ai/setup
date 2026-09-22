"""Stub stand-in for onboard.py used by the onboard.ps1 test battery.

onboard.ps1 downloads onboard.py and runs it as a native child. This stub takes
its place so the harness can choose the child's exit code and stdout volume:

  UNBOUND_TEST_CHILD_EXIT   exit code to return (default 0)
  UNBOUND_TEST_STDOUT_LINES lines to print to stdout (default 5)

Multi-line stdout is deliberate: on the pre-change onboard.ps1 those lines land
on Main's success stream and become part of the object[] that masks the code.
The stderr line mimics onboard.py logging to stderr under $ErrorActionPreference
= 'Continue'. This file makes no network calls and touches nothing.
"""

import os
import sys


def main() -> int:
    code = int(os.environ.get("UNBOUND_TEST_CHILD_EXIT", "0"))
    lines = int(os.environ.get("UNBOUND_TEST_STDOUT_LINES", "5"))
    for i in range(1, lines + 1):
        print(f"[stub] stdout line {i}")
    print("[stub] diagnostic on stderr", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
