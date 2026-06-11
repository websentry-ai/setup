#!/usr/bin/env python3
"""Binary entry point for the unbound-discovery PyInstaller bundle.

Thin wrapper around coding_discovery_tools.ai_tools_discovery.main(). The one
behavioral addition lives at the packaging boundary: the binary is installed
fleet-wide by MDM and runs from a root LaunchDaemon, so it can start before
per-tenant configuration (--api-key/--domain) has been delivered. In that
no-config state the script itself would exit 1; a daemon must instead idle
cleanly (fail-open) — log one line and exit 0.

Everything else (argument semantics, detection, reporting via curl) is the
upstream script, unchanged.
"""
import logging
import sys

REQUIRED_ARGS = ("--api-key", "--domain")


def _missing_required_args(argv):
    """Return required arg names that are absent or have an empty value."""
    values = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        for name in REQUIRED_ARGS:
            if arg == name:
                values[name] = argv[i + 1] if i + 1 < len(argv) else ""
            elif arg.startswith(name + "="):
                values[name] = arg.split("=", 1)[1]
        i += 1
    return [name for name in REQUIRED_ARGS if not values.get(name)]


def main():
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        from coding_discovery_tools.ai_tools_discovery import main as discovery_main

        discovery_main()
        return 0

    missing = _missing_required_args(sys.argv[1:])
    if missing:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        logging.getLogger("unbound-discovery").info(
            "No configuration provided (missing: %s); discovery has nothing to "
            "do and is idling (fail-open). Exiting 0.",
            ", ".join(missing),
        )
        return 0

    from coding_discovery_tools.ai_tools_discovery import main as discovery_main

    discovery_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
