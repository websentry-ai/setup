"""`unbound-hook clear` — full deregistration.

Reuses each vendored MDM module's clear_setup() verbatim (system env vars
from every user's rc files, managed/enterprise hook settings, codex feature
flag, per-user copilot hooks, cursor restart) — those writers operate on the
same files whether the registered command was python or the binary — then
removes the legacy per-user remote-fetch discovery LaunchAgents.

Parity note: like the python --clear, this does NOT remove
~/.unbound/config.json. The pkg-owned system LaunchDaemon is left to the
pkg's own uninstall.
"""

import sys

from ._loader import load_mdm_setup_module
from . import migration

CLEAR_TOOLS = ("claude-code", "cursor", "codex", "copilot")


def run(argv) -> int:
    for a in argv:
        if a != "--debug":
            print(f"Unknown argument: {a}", file=sys.stderr)
            print("Usage: unbound-hook clear [--debug]", file=sys.stderr)
            return 2

    m0 = load_mdm_setup_module("claude-code")
    if not m0.check_admin_privileges():
        print("unbound-hook clear requires administrator/root privileges. Re-run with sudo.",
              file=sys.stderr)
        return 1

    failures = []
    for tool in CLEAR_TOOLS:
        print(f"\n{'=' * 60}\n[{tool}] clear\n{'=' * 60}")
        try:
            m = load_mdm_setup_module(tool)
            m.DEBUG = True
            m.clear_setup()
        except SystemExit:
            failures.append(tool)
        except Exception as e:
            print(f"[{tool}] clear failed: {e}", file=sys.stderr)
            failures.append(tool)

    print(f"\n{'=' * 60}\n[migration] removing legacy discovery LaunchAgents\n{'=' * 60}")
    status, reason = migration.run_sweep()
    if status == "deferred":
        print(f"[migration] {reason}", file=sys.stderr)
        failures.append("migration")

    if failures:
        print(f"\nClear finished with failure(s): {', '.join(failures)}", file=sys.stderr)
        return 1
    print("\nClear complete.")
    return 0
