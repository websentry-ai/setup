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


def _force_utf8_io() -> None:
    """Make stdout/stderr never raise on non-ASCII output.

    Under an interactive shell the inherited locale is UTF-8, so Python
    selects a UTF-8 codec for stdout. But Jamf's recurring check-in runs the
    onboarding policy from a launchd context with no LANG/LC_* set, where
    Python falls back to the ASCII codec. A single non-ASCII character in any
    line we print — the migration banner's arrow, a unicode username, a tool
    path — then raises UnicodeEncodeError and aborts the entire run, even
    though the output itself is purely diagnostic. (This crashed Salesloft's
    fleet at `setup` on every Jamf check-in while interactive `sudo jamf
    policy` runs passed.)

    Reconfiguring to UTF-8 with errors='replace' makes output best-effort: a
    cosmetic print can never kill the real work (settings writes, discovery).
    It is also correct for the `hook` path, whose stdout carries UTF-8 JSON.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Detached/closed stream — nothing we can do, and not worth
            # crashing onboarding over.
            pass

USAGE = """unbound-hook %s

Usage:
  unbound-hook hook <tool> [<event>]      tools: claude-code|cursor|copilot|codex|augment
  unbound-hook setup --api-key <key> [--discovery-key <key>] [options]
  unbound-hook backfill (--all | --user <name>) [--dry-run] [options]
  unbound-hook clear
  unbound-hook --version
""" % __version__


def main(argv=None) -> int:
    _force_utf8_io()
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
