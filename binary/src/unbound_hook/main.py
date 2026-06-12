"""unbound-hook CLI entry point.

Subcommands:
  hook <tool> [<event>]   stdin/stdout hook dispatch (fail-open, exit 0)
  setup [...]             MDM onboarding (port of mdm/onboard.py)
  backfill [...]          historical transcript seeding
  clear [...]             full deregistration
  --version / version     print version (pkg postinstall pre-warm contract:
                          must exit fast without reading stdin)
"""

import sys

from . import __version__

USAGE = """unbound-hook %s

Usage:
  unbound-hook hook <tool> [<event>]      tools: claude-code|cursor|copilot|codex
  unbound-hook setup --api-key <key> [--discovery-key <key>] [options]
  unbound-hook backfill (--all | --user <name>) [--dry-run] [options]
  unbound-hook clear
  unbound-hook --version
""" % __version__


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if args and args[0] in ("--version", "-V", "version"):
        print(f"unbound-hook {__version__}")
        return 0
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if args else 2

    cmd, rest = args[0], args[1:]
    if cmd == "hook":
        from . import hook_cmd
        return hook_cmd.run(rest)
    if cmd == "setup":
        from . import setup_cmd
        return setup_cmd.run(rest)
    if cmd == "backfill":
        from . import backfill_cmd
        return backfill_cmd.run(rest)
    if cmd == "clear":
        from . import clear_cmd
        return clear_cmd.run(rest)

    print(f"Unknown command: {cmd}", file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
