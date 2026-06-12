"""`unbound-hook backfill` — historical transcript seeding from the binary.

Reuses the vendored MDM modules' backfill machinery wholesale: collection,
exchange-boundary chunking with record_index_base (which keeps the server's
per-record uuid5 seed stable), S3 staging, Task-row idempotent import, and
the per-home mtime-cutoff bookkeeping. Cursor has no transcript store.
Default tools are claude-code + codex (the WEB-4786 scope); copilot also
has backfill machinery and can be opted in via --tools (setup's --backfill
runs it, mirroring mdm/onboard.py).

  unbound-hook backfill --all [--tools claude-code,codex] [--dry-run]
  unbound-hook backfill --user <name> [...]

The api key + backend url come from the target users' ~/.unbound/config.json
(written by setup); --backend-url overrides the url.
"""

import json
import sys
from pathlib import Path

from ._loader import load_mdm_setup_module

BACKFILL_TOOLS_DEFAULT = ("claude-code", "codex")
BACKFILL_CAPABLE = ("claude-code", "codex", "copilot")

USAGE = (
    "Usage: unbound-hook backfill (--all | --user <name>) [--dry-run]\n"
    "           [--tools claude-code,codex] [--backend-url <url>]\n"
)


def _parse_args(argv):
    opts = {"user": None, "all": False, "dry_run": False,
            "tools": list(BACKFILL_TOOLS_DEFAULT), "backend_url": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--user" and i + 1 < len(argv):
            opts["user"] = argv[i + 1]; i += 2
        elif a == "--all":
            opts["all"] = True; i += 1
        elif a == "--dry-run":
            opts["dry_run"] = True; i += 1
        elif a == "--tools" and i + 1 < len(argv):
            opts["tools"] = [t.strip() for t in argv[i + 1].split(",") if t.strip()]
            i += 2
        elif a == "--backend-url" and i + 1 < len(argv):
            opts["backend_url"] = argv[i + 1]; i += 2
        else:
            print(f"Unknown argument: {a}", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return None
    return opts


def _read_user_config(m, username, home_dir):
    """Read ~/.unbound/config.json privilege-dropped as the owning user."""
    config_path = home_dir / ".unbound" / "config.json"

    def _read():
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    result = m._run_as_user(username, _read)
    return result if isinstance(result, dict) else None


def run(argv) -> int:
    opts = _parse_args(argv)
    if opts is None:
        return 2
    if bool(opts["user"]) == bool(opts["all"]):
        print("Error: pass exactly one of --user <name> or --all.", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    m0 = load_mdm_setup_module("claude-code")
    if not m0.check_admin_privileges():
        print("unbound-hook backfill requires administrator/root privileges.", file=sys.stderr)
        return 1

    user_homes = m0.get_all_user_homes()
    if opts["user"]:
        user_homes = [(u, h) for u, h in user_homes if u == opts["user"]]
        if not user_homes:
            print(f"Error: no home directory found for user {opts['user']!r}.", file=sys.stderr)
            return 1

    # Device-wide key: every profile's config carries the same per-device
    # api key (the model run_backfill documents). First readable one wins.
    api_key = None
    backend_url = m0.normalize_url(opts["backend_url"]) if opts["backend_url"] else None
    for username, home_dir in user_homes:
        cfg = _read_user_config(m0, username, home_dir) or {}
        api_key = api_key or cfg.get("api_key")
        backend_url = backend_url or cfg.get("base_url")
        if api_key and backend_url:
            break
    if not opts["dry_run"] and (not api_key or not backend_url):
        print("Error: no api_key/base_url found in ~/.unbound/config.json for the "
              "selected users — run `unbound-hook setup` first.", file=sys.stderr)
        return 1

    exit_code = 0
    for tool in opts["tools"]:
        if tool not in BACKFILL_CAPABLE:
            print(f"[backfill] {tool}: not supported — skipping.")
            continue
        m = load_mdm_setup_module(tool)
        m.DEBUG = True
        print(f"\n[backfill] tool={tool}")
        if opts["dry_run"]:
            try:
                total_sessions = 0
                for username, home_dir in user_homes:
                    result = m._run_as_user(username, m._backfill_collect_sessions, home_dir)
                    if result is None:
                        print(f"  {username}: unreadable (skipped)")
                        continue
                    sessions, capped = result
                    total_sessions += len(sessions)
                    note = " (capped — more remain)" if capped else ""
                    print(f"  {username}: {len(sessions)} session(s) eligible{note}")
                print(f"  dry-run: {total_sessions} session(s) would be uploaded; "
                      f"no uploads performed, cutoffs not advanced.")
            except Exception as e:
                # Same loud-failure contract as the upload path below: report
                # the tool's failure and surface it in the exit code instead
                # of crashing out of the remaining tools.
                print(f"[backfill] {tool}: dry-run failed: {e}", file=sys.stderr)
                exit_code = 1
            continue
        try:
            m.run_backfill(api_key, backend_url, user_homes)
        except Exception as e:
            print(f"[backfill] {tool}: failed: {e}", file=sys.stderr)
            exit_code = 1
    return exit_code
