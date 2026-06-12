#!/usr/bin/env python3
"""PLACEHOLDER entry point for the `unbound-discovery` binary (Stream B, WEB-4787).

Stdlib-only stand-in so the release pipeline (WEB-4789) can build, sign,
package, and smoke-test end-to-end before the real discovery runtime lands.
The real build checks out websentry-ai/coding-discovery-tool at the SHA in
packaging/discovery.lock and Stream B's .spec points at its entry module.

Contract the LaunchDaemon (WEB-4792) relies on and the real binary must keep:
  * `unbound-discovery --version` prints version, exit 0
  * `unbound-discovery scan` with NO config present idles gracefully and
    exits 0 (fail-open) — the daemon is installed by the pkg before
    onboard.sh has written any config, and must not crash-loop.
  * zero network code fetch: everything it runs ships inside the bundle.
"""

import os
import sys

VERSION = "0.0.0-placeholder"

CONFIG_PATH = "/opt/unbound/etc/discovery.json"


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("--version", "-V", "version"):
        print(f"unbound-discovery {VERSION}")
        return 0

    if args[0] == "scan":
        if not os.path.exists(CONFIG_PATH):
            # Fail-open idle: no config yet (pkg installed, onboard.sh not run).
            print("unbound-discovery: no config present; idling (fail-open).")
            return 0
        print(f"unbound-discovery {VERSION}: 'scan' is a placeholder no-op "
              "(real implementation lands with Stream B)")
        return 0

    print(f"unbound-discovery: unknown command {args[0]!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
