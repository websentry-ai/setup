# unbound-hook — self-contained hook binary (WEB-4786 / WEB-4788)

PyInstaller `--onedir` universal2 CLI for Mac fleets with **no python3 / no
Xcode CLT**. One binary serves all four tools' hooks plus MDM setup,
transcript backfill, and deregistration. Spike results: `SPIKE.md`.

```
unbound-hook hook <tool> [<event>]     # claude-code | cursor | copilot | codex
unbound-hook setup --api-key <admin_key> [--discovery-key <key>]
                   [--backend-url <url>] [--gateway-url <url>] [--frontend-url <url>]
                   [--app_name <name>] [--backfill] [--tools t1,t2]
unbound-hook backfill (--all | --user <name>) [--dry-run] [--tools claude-code,codex]
unbound-hook clear
unbound-hook --version                 # pkg postinstall pre-warm contract
```

## Design: the python modules ARE the binary

The four hook modules (`claude-code/hooks/unbound.py`, `cursor/unbound.py`,
`copilot/hooks/unbound.py`, `codex/hooks/unbound.py`) and the four MDM setup
modules ship inside the bundle as **source data files** (`vendored/`), loaded
with importlib at runtime. The binary executes the exact bytes the python
serving path executes — behavior can't drift between the two. The python
serving paths remain fully functional and untouched in semantics.

`hook <tool>` loads the tool's module and calls its `main()`: stdin event
JSON → stdout response JSON, unchanged. The `<event>` argv exists because
managed settings register one command per event; the modules dispatch on the
payload's `hook_event_name` (argv is routing/diagnostics only). The tool
argv IS load-bearing: claude-code/copilot/codex share event names, so the
event alone can't select a module. Dispatcher failures fail open (`{}`,
exit 0) — this process sits between the user and their editor.

## Frozen-mode gates (in the modules, inert under python)

When `sys.frozen` (or `UNBOUND_HOOK_FROZEN=1` for tests):

- `_check_self_update` no-ops — the MDM pkg owns binary updates; no
  raw.githubusercontent fetch ever
- `_dispatch_discovery` / `_dispatch_mcp_server_scan` run
  `/opt/unbound/current/unbound-discovery/unbound-discovery` directly
  (`--domain` / `mcp-scan --name --domain`, same env contract as the
  install.sh bootstrap). Missing binary → log + skip; **no network
  fallback**. The frozen hook path makes zero network calls except the
  backend/gateway APIs.

**Contract with the `unbound-discovery` binary (WEB-4792 track — verify
before pkg rollout):** accepts `--domain <url>` for a full sweep and
`mcp-scan --name <n> --domain <url>` for single-server scans; reads the api
key from the `UNBOUND_API_KEY` env var (never argv); honors
`UNBOUND_MCP_SERVER_JSON`/`UNBOUND_MCP_SERVER_NAME`/`UNBOUND_MCP_DOMAIN`
for mcp-scan. This mirrors install.sh's pass-through interface; nothing in
this repo can pin it, so it's asserted here as a cross-stream contract.

## setup

In-binary port of `mdm/onboard.py` + the per-tool `mdm/setup.py` flows,
reusing the vendored modules' own functions (privilege drop, env vars,
per-user config, user-hook strips, backfill, completion notify). Deltas from
the python path, by design:

- **No downloads.** No SCRIPT_URL setup.py/unbound.py fetches, no
  install.sh; discovery runs the locally installed binary.
- **Managed hook commands** point at
  `"/opt/unbound/current/unbound-hook/unbound-hook" hook <tool> <event>`.
  Settings JSON structure and per-event timeouts are copied verbatim —
  including PreToolUse's historical `timeout: 15000` next to `60` elsewhere
  (units intentionally NOT normalized; changing them is a behavior change).
- **Per-component status** (`configured | skipped(reason) | deferred(reason)`)
  with fail-open orchestration: a component failure is reported in the
  summary + exit code but never aborts the others. `deferred` means a re-run
  should retry; `skipped` is intentional.
- **`detect_install_state`** is adapted: the python version checked for the
  managed `unbound.py`, which no longer exists. Binary semantics: settings
  file absent → `fresh`; present and referencing the binary → `persisted`;
  present without → `tampered`.

## Migration sweep (WEB-4788)

Runs first inside `setup` (and after `clear`); idempotent, existence-guarded:

- bootout per-user remote-fetch discovery LaunchAgents
  (`ai.getunbound.scheduled` + legacy `ai.getunbound.discovery`) from the
  **gui/<uid> domain only** — the new pkg LaunchDaemon reuses the
  `ai.getunbound.discovery` label in the system domain and must survive
- remove `~/.local/share/unbound/{install.sh,run-scheduled.sh}`, stale
  `unbound.py` + `.self_update_check`/`.self_update.lock` in each tool's
  hooks dir, and the managed (system) `unbound.py` copies
- strip user-mode hook registrations via each module's own stripper
  (user-authored hooks survive)
- `~/.unbound/config.json` is never touched

## backfill / clear

`backfill` reuses the modules' collection → exchange-boundary chunking
(`record_index_base` keeps the server's per-record uuid5 seed stable) → S3
staging → Task-row-idempotent import, plus the per-home mtime cutoffs.
`--dry-run` collects and reports without uploading or advancing cutoffs.
`clear` reuses each module's `clear_setup()` (env vars, managed settings,
codex feature flag, copilot per-user files, cursor restart) and then removes
the legacy LaunchAgents. Parity: like python `--clear`, it keeps
`~/.unbound/config.json`.

## Build & test

```
./build.sh                      # needs python.org CPython 3.12 universal2 (UNBOUND_BUILD_PYTHON to override)
python -m pytest tests/        # CLI-boundary parity per tool per event + setup/migration fixtures
```

`build.sh` gates on: hidden-import drift (vendored sources vs spec), every
Mach-O being universal2, and a smoke run. Tests compare the CLI (dev entry
and built binary) against `python3 <tool>/unbound.py` for stdout + exit-code
equality on every tool × event, malformed input included.

Not in scope here: codesigning/notarization (cert track), the pkg payload /
LaunchDaemon / `current` symlink (WEB-4792), Windows.
