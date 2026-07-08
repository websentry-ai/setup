#!/usr/bin/env python3
"""Binary entry point for the unbound-discovery PyInstaller bundle.

Thin wrapper around coding_discovery_tools.ai_tools_discovery.main(). The one
behavioral addition lives at the packaging boundary: the binary is installed
fleet-wide by MDM and runs from a root LaunchDaemon, so it can start before
per-tenant configuration has been delivered. In that no-config state the
script itself would exit 1; a daemon must instead idle cleanly (fail-open) —
log one line and exit 0.

Configuration is considered present when both the API key (--api-key flag, the
UNBOUND_API_KEY env var mirroring upstream, or the persisted root-only config
file) and --domain (flag or config file) are non-empty. The config file
(/opt/unbound/etc/discovery.json, written 0600 by `unbound-hook setup`) is the
credential channel for the scheduled root LaunchDaemon, which sees no shell env
and whose world-readable plist intentionally carries no secrets (WEB-4808).

Subcommand routing mirrors upstream install.sh at the pinned SHA: a leading
"mcp-scan" runs the on-demand single-server scan (scan_single_mcp_server,
used by the agent hooks when the gateway reports an unknown MCP server). A
leading "scan" token (the LaunchDaemon's invocation) is stripped — the full
sweep is the bare/default invocation and upstream's strict argparse would
otherwise reject "scan" once creds resolve. Anything else runs the full
discovery sweep. Everything else (argument semantics, detection, reporting via
curl) is the upstream script, unchanged.
"""
import argparse
import json
import logging
import os
import sys

# Root-only credential file written by `unbound-hook setup` at onboard time
# (setup_cmd._write_discovery_config). The scheduled LaunchDaemon runs as root
# with no shell environment, so a key in a user's shell rc is invisible to it,
# and the plist deliberately carries no secrets (it is world-readable). This
# file is the credential channel for the recurring scan (WEB-4808). It is an
# OPTIONAL fallback: when it is absent or unreadable (pre-onboarding, partial
# install) credential resolution falls through to the existing missing-config
# idle path — discovery must never crash or block dev work because of it.
DISCOVERY_CONFIG_PATH = "/opt/unbound/etc/discovery.json"

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


def _load_discovery_config(path=None):
    """Best-effort read of the root-only discovery config (api_key, domain).

    Returns a {"api_key": str, "domain": str} dict with only the non-empty
    string values present. Any failure — file absent, unreadable, not JSON,
    not an object, wrong value types — returns {} so the caller falls through
    to the fail-open idle path. This function NEVER raises: a credential file
    problem must not turn a quiet idle into a crash on a root daemon.

    `path` defaults to the module-level DISCOVERY_CONFIG_PATH resolved at CALL
    time (not bound at def time) so tests can redirect it.
    """
    if path is None:
        path = DISCOVERY_CONFIG_PATH
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for key in ("api_key", "domain"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value
    return out


def _resolve_config(argv):
    """Resolve (api_key, domain) from flags/env, then the config file.

    Precedence per field, highest first: explicit flag / env (the existing
    contract) > the persisted root-only config file (WEB-4808 daemon channel).
    The config file only FILLS fields that are otherwise absent; it never
    overrides an explicit flag or env value. Returns (api_key, domain) as
    possibly-empty strings.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--api-key")
    parser.add_argument("--domain")
    ns, _ = parser.parse_known_args(argv)

    api_key = (ns.api_key or os.environ.get("UNBOUND_API_KEY") or "").strip()
    domain = (ns.domain or "").strip()

    if not api_key or not domain:
        cfg = _load_discovery_config()
        if not api_key:
            api_key = cfg.get("api_key", "")
        if not domain:
            domain = cfg.get("domain", "")
    return api_key, domain


def _missing_required_config(argv):
    """Return human-readable names of required config that is absent/empty.

    Resolution honors the UNBOUND_API_KEY env fallback exactly like upstream
    main() and, when a field is still absent, the persisted root-only config
    file (WEB-4808) so the scheduled root daemon — which sees no shell env and
    has no secrets in its world-readable plist — can find its credentials.
    """
    api_key, domain = _resolve_config(argv)
    missing = []
    if not api_key:
        missing.append("--api-key (or UNBOUND_API_KEY env)")
    if not domain:
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

    # Strip a leading "scan" token the same way "mcp-scan" is shifted off:
    # the production LaunchDaemon invokes `unbound-discovery scan`, but the
    # full-sweep is the default (bare) invocation and upstream's strict
    # argparse rejects an unknown positional. With no creds the lenient
    # parse_known_args tolerated it (idle path), masking the bug; the moment
    # creds resolve, an unstripped "scan" would SystemExit(2). Stripping it
    # here keeps the world-readable plist free of secrets AND lets the
    # credentialed sweep run (WEB-4808). No-op when "scan" is absent.
    if argv and argv[0] == "scan":
        argv = argv[1:]
        sys.argv = [sys.argv[0]] + argv

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

    # Config is present (from flags/env and/or the persisted config file).
    # Upstream main() reads creds only from --api-key/UNBOUND_API_KEY/--domain,
    # so feed any file-sourced values through those same channels. The key goes
    # via env (the argv-free channel) to keep it out of `ps`; the domain is not
    # secret and goes via argv. Explicit flags/env already in sys.argv win —
    # _resolve_config only fills absent fields — so this never overrides them.
    api_key, domain = _resolve_config(argv)
    if not os.environ.get("UNBOUND_API_KEY"):
        os.environ["UNBOUND_API_KEY"] = api_key
    if "--domain" not in sys.argv and not any(
        a.startswith("--domain=") for a in sys.argv
    ):
        sys.argv = sys.argv + ["--domain", domain]

    from coding_discovery_tools.ai_tools_discovery import main as discovery_main

    try:
        discovery_main()
    except Exception:
        _log_crash()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
