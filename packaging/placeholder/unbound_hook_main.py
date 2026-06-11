#!/usr/bin/env python3
"""PLACEHOLDER entry point for the `unbound-hook` binary (Stream A, WEB-4786).

Stdlib-only stand-in so the release pipeline (WEB-4789) can build, sign,
package, and smoke-test end-to-end before the real hook runtime lands.
Stream A replaces this module (and packaging/specs/unbound-hook.spec keeps
pointing at the real entry point) — the CLI surface exercised by the
pipeline must stay stable:

  unbound-hook --version          -> prints version, exit 0
  unbound-hook hook               -> reads one JSON event from stdin, exit 0
  unbound-hook setup [flags...]   -> exit 0 (real impl: per-tool MDM setup)
  unbound-hook clear [flags...]   -> exit 0 (real impl: teardown)
"""

import json
import sys

# Replaced by the real runtime's version module; the placeholder reports a
# clearly-fake version so a placeholder binary can never be mistaken for a
# released runtime.
VERSION = "0.0.0-placeholder"


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("--version", "-V", "version"):
        print(f"unbound-hook {VERSION}")
        return 0

    cmd = args[0]
    if cmd == "hook":
        try:
            event = json.load(sys.stdin)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"unbound-hook: invalid event JSON: {e}", file=sys.stderr)
            return 1
        # Fail-open contract: the placeholder always allows.
        print(json.dumps({"decision": "allow", "placeholder": True,
                          "event_keys": sorted(event) if isinstance(event, dict) else []}))
        return 0

    if cmd in ("setup", "clear"):
        print(f"unbound-hook {VERSION}: '{cmd}' is a placeholder no-op "
              "(real implementation lands with Stream A)")
        return 0

    print(f"unbound-hook: unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
