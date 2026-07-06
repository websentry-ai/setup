#!/usr/bin/env python3
"""Binary entry point for the unbound-discovery PyInstaller bundle.

Thin wrapper around coding_discovery_tools.ai_tools_discovery.main(). The one
behavioral addition lives at the packaging boundary: the binary is installed
fleet-wide by MDM and runs from a root LaunchDaemon, so it can start before
per-tenant configuration has been delivered. In that no-config state the
script itself would exit 1; a daemon must instead idle cleanly (fail-open) —
log one line and exit 0.

Configuration is considered present when both the API key (--api-key flag or
the UNBOUND_API_KEY env var, mirroring upstream) and --domain are non-empty.

Subcommand routing mirrors upstream install.sh at the pinned SHA: a leading
"mcp-scan" runs the on-demand single-server scan (scan_single_mcp_server,
used by the agent hooks when the gateway reports an unknown MCP server);
anything else runs the full discovery sweep. Everything else (argument
semantics, detection, reporting via curl) is the upstream script, unchanged.
"""
import argparse
import logging
import os
import sys

# Discovery's user-facing version. Mirrors unbound-hook's __version__
# (binary/src/unbound_hook/__init__.py) so both binaries report the same
# string. The release workflow's publish-safety assert requires
# `<bin> --version` to contain the release version space-delimited
# (release-macos-runtime.yml: `[[ " $v_out " != *" $VERSION "* ]]`).
#
# TODO(WEB-4802): hook and discovery versions must be bumped in lockstep on
# every tag until build-time version injection lands (the workflow already
# notes this). Keep this equal to unbound_hook.__version__ until then.
__version__ = "0.1.11"


def _missing_required_config(argv):
    """Return human-readable names of required config that is absent/empty.

    Uses an argparse mirror (not a hand-rolled scan) so '=', value-consumption
    and prefix-abbreviation semantics match the upstream parser, and honors
    the UNBOUND_API_KEY env fallback exactly like upstream main().
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--api-key")
    parser.add_argument("--domain")
    ns, _ = parser.parse_known_args(argv)

    api_key = ns.api_key or os.environ.get("UNBOUND_API_KEY") or ""
    missing = []
    if not api_key.strip():
        missing.append("--api-key (or UNBOUND_API_KEY env)")
    if not (ns.domain or "").strip():
        missing.append("--domain")
    return missing


def _log_crash():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("unbound-discovery").exception(
        "unbound-discovery crashed with an unhandled exception"
    )


def main():
    argv = sys.argv[1:]

    # Version pre-check: must run BEFORE config parsing / the no-config idle
    # path, otherwise `--version` falls through to the fail-open idle branch
    # which logs to stderr and leaves stdout empty — tripping the release
    # workflow's publish-safety assert (WEB-4802). Mirrors unbound-hook's
    # contract: print "<name> <version>" to stdout, exit 0, read no stdin.
    if argv and argv[0] in ("--version", "-V"):
        print(f"unbound-discovery {__version__}")
        return 0

    if argv and argv[0] == "mcp-scan":
        # Same shift as install.sh: the subcommand token must not reach the
        # module's argparse. Its main() returns an exit code (0 ok/skip,
        # 1 scan/report failure, 2 config error).
        sys.argv = [sys.argv[0]] + argv[1:]
        from coding_discovery_tools.scan_single_mcp_server import main as mcp_scan_main

        try:
            return mcp_scan_main()
        except Exception:
            _log_crash()
            return 1

    if "-h" in argv or "--help" in argv:
        from coding_discovery_tools.ai_tools_discovery import main as discovery_main

        discovery_main()
        return 0

    missing = _missing_required_config(argv)
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

    try:
        discovery_main()
    except Exception:
        _log_crash()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
