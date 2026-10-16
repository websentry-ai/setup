# opencode: MDM / all-users installer

`setup.py` in this directory installs the Unbound plugin for opencode for **every real user on a
device**, in one root run, from an MDM (Jamf and friends). It is the root counterpart of
[`opencode/setup.py`](../README.md); the plugin's own scope is in
[`hooks-ts/docs/OPENCODE.md`](../../hooks-ts/docs/OPENCODE.md).

## Read this first: what this does and does not buy you

This is **advisory control over a machine whose user may administer it**, not tamper resistance.
Each of these starts opencode without the plugin, and nothing in this script can prevent it:

- `opencode --pure` or `OPENCODE_PURE=1`: no plugin is loaded at all, including the managed
  reference below (spike V1-10);
- `XDG_CONFIG_HOME`, `OPENCODE_CONFIG_DIR` or `HOME` pointed elsewhere: opencode reads per-user
  plugins from a directory this push did not write;
- `OPENCODE_PERMISSION`: turns off opencode's own approval rules (Unbound checks still run).

Deploy it for coverage by default, not for a guarantee.

## Operator command

```sh
sudo python3 setup.py --api-key <admin api key> \
    [--backend-url https://backend.getunbound.ai] \
    [--gateway-url https://api.getunbound.ai] \
    [--frontend-url https://app.getunbound.ai] \
    [--app_name "<application name>"] \
    [--debug]

sudo python3 setup.py --clear [--debug]
```

`--api-key` takes an **admin** application key. It is exchanged **once per device** (with
`app_type=opencode`) for this org's opencode application key, and it never appears on a `curl`
argv: it travels in a `0600` temp header file. Root is required; without it the script prints one
line and exits `1` without touching any home. MDM runs always force debug logging on.

## What lands on disk

**Per enumerated user** (the baseline; both opencode lines):

| Path | Mode | Owner |
|---|---|---|
| `<home>/.config/opencode/plugins/unbound.js` | `0644` | that user |
| `<home>/.config/opencode/plugins/unbound.js.sha256` | `0644` | that user |
| `<home>/.config/opencode/plugins/package.json` = `{"type":"module"}`, only when absent and no other plugin lives there | `0644` | that user |
| `<home>/.config/opencode/plugins/.unbound-installed.json` (what `--clear` may remove) | `0644` | that user |
| an `export UNBOUND_OPENCODE_API_KEY="…"` line in `~/.zprofile` + the user's bash login profile (macOS) or `~/.zshrc` + `~/.bashrc` (Linux) | group/other bits stripped | that user |
| `api_key` in `<home>/.unbound/config.json`, **only when absent or previously written by this installer** (`opencode_mdm_api_key_sha256` beside it marks it as ours) | `0600` in a `0700` dir | that user |

Per home, the same two rules as the per-user installer run with privileges dropped: stray Unbound
copies that would load twice (`plugin/unbound.js`, `plugins/unbound.ts`, `plugin/unbound.ts`) are
removed when recognised as Unbound's, and the ESM `package.json` is created only in the safe case.
No per-user opencode config file is written.

**Once per device, opencode 1.x only: the managed reference** (spike V1-8, proven on
opencode-ai 1.18.34):

| Path | Mode | Owner |
|---|---|---|
| `<managed>/unbound/unbound.js` | `0644` | root |
| `<managed>/unbound/unbound.js.sha256`, `<managed>/unbound/package.json` (`{"type":"module"}`) | `0644` | root |
| `<managed>/unbound/.unbound-installed.json` (what `--clear` may remove) | `0644` | root |
| one `file://` entry in `<managed>/opencode.json` `plugin` | file mode kept (`0644` when created) | root |

`<managed>` is `/Library/Application Support/opencode` on macOS and `/etc/opencode` on Linux.
Windows is not supported for the managed reference. opencode 1.x reads only `opencode.json[c]`
from the managed dir (it does not scan it for plugin files), so the plugin is referenced by its
absolute, percent-encoded URL, for example
`file:///Library/Application%20Support/opencode/unbound/unbound.js`. The merge:

- keeps every existing key and every other `plugin` entry, in order;
- is idempotent: a rerun that finds the entry leaves `opencode.json` byte-identical;
- never touches a managed `opencode.jsonc` (comments) or an `opencode.json` that is not strict JSON
  or whose `plugin` is not a list: the step is then reported as `skipped (…)` and nothing is
  written to the managed dir.

**Why both.** opencode 2.x did not load the managed reference in the same spike, so the per-home
drop stays the baseline for every account. Where opencode 1.x loads both copies (same build), the
second one is inert and the plugin reports one `duplicate_load` signal per opencode process;
policy checks run once. The managed copy cannot be deleted by a non-root user, but `--pure` still
skips it. A failed managed step is printed and does not fail the run: the per-home plugin is
unaffected.

**Default config dir only.** `OPENCODE_CONFIG_DIR` and `XDG_CONFIG_HOME` belong to the *target
user's* environment, which root cannot read; reading root's own copy would install every user's
plugin into one shared directory. So the per-home drop covers `<home>/.config/opencode` only (on
macOS too). On opencode 2.x, `OPENCODE_CONFIG_DIR` **replaces** that directory, so a user who sets
it is not covered by this push and must run the per-user `unbound setup opencode`.

## Writing into another user's home as root

Every in-home write goes through the three primitives of `pi/mdm/setup.py`, unchanged:
`_run_as_user` (fork, then `setgroups` / `setgid` / `setuid` before touching anything),
`_repair_user_ownership` (a component-wise `O_NOFOLLOW` walk anchored at the passwd home, then
`fchown` on the descriptor; hard-linked files refused; the home itself never chowned), and an
`O_NOFOLLOW` temp + rename for the plugin itself. A symlinked `unbound.js` is refused. One
unwritable home costs that user their coverage and nothing more; the loop continues and prints a
per-user table, followed by the managed reference's status.

## What counts as a successful push

An account is covered only when **both** halves landed: the plugin, and a key it can read (the
`UNBOUND_OPENCODE_API_KEY` export or `api_key` in `~/.unbound/config.json`). A run where no account
got a key exits `1` even though every `unbound.js` is on disk; the plugin is left in place and the
next push repairs the key.

## Restart and remote servers

opencode loads plugins at startup. **Each user must restart opencode** (quit and relaunch the
OpenCode desktop app) after a push or a `--clear`. Plugins run where the opencode server runs: if a
user runs `opencode serve`, `opencode attach` or the desktop app's background service on another
machine, push this to the machine where the server runs.

## What is enforced

As in the per-user README: on opencode 1.18.x, model tool calls, MCP calls, subagent tool calls,
root prompts and the user `!cmd`; **OpenCode 2.x is enforced** too (tool calls, MCP, prompts, the
user shell, with OpenCode's native approval prompt for approval verdicts). Not hooked: shell inside
custom slash-command templates, the integrated terminal, processes opencode starts from config, and
remote `attach` clients except through their server. Full table:
[`hooks-ts/docs/OPENCODE.md`](../../hooks-ts/docs/OPENCODE.md).

## The integrity sidecar, honestly

The artifact and `opencode/index.js.sha256` are downloaded and verified **once**, before the home
loop, so a bad artifact reaches zero homes and no managed dir. The sidecar comes from the same
origin, TLS and ref as the artifact: it catches truncation, corruption and staleness and gives the
backend an honest `hook_hash`, but it is **not** a supply-chain control.

## Reporting

Exactly one report per device run, after the loop:

```
POST /api/v1/setup/complete/
{"tool_type": "opencode", "install_state": "fresh|persisted", "serial_number": "<device serial>",
 "hook_hash": "<sha256 of the installed unbound.js>", "install_mode": "mdm"}
```

`install_state` is read before any home is written. A report failure prints one line and does not
change the exit status. The device-level `install-report` endpoint (Jamf bootstrap telemetry, no
`tool_type`) is deliberately not used. `--clear` reports nothing.

## `--clear`

Per home: removes `unbound.js`, `unbound.js.sha256`, `package.json` only when the marker lists it
and it is unchanged, the marker, and the `UNBOUND_OPENCODE_API_KEY` export line. Leaves the
`plugins/` directory, every other file in it, and `~/.unbound/config.json` entirely alone (its
`api_key` is shared with the other Unbound tools).

Managed dir: removes only our `plugin` entry, our copy, sidecar, `package.json` and marker, and the
`unbound/` directory when it is then empty. `opencode.json` itself is deleted only when it is then
`{}` **and** the marker says this installer created it; a `plugin` key this installer added is
dropped again once it is empty. If `opencode.json` is no longer strict JSON, our entry **and** our
copy are left in place and the status says `kept (…)`, so opencode is never left pointing at a
missing file. No network call; without root it refuses cleanly.

## Not registered in `mdm/onboard.py`

opencode is deliberately not in `mdm/onboard.py`'s `TOOLS` list, so the Jamf bootstrap does not run
it automatically; run this script directly from an MDM policy.

## Home enumeration

| Platform | Source | Rule |
|---|---|---|
| macOS | `pwd.getpwall()` | `uid >= 500`, home exists and is a directory, under the `Users` prefix, name not `Shared` or `Guest` |
| Linux | `pwd.getpwall()` | `uid >= 1000`, home exists and is a directory, under the `home` prefix |
| Windows | the profile directories under `%SystemDrive%\Users` | skip `Public`, `Default`, `Default User`, `Administrator`, `All Users` |

Any failure yields an empty list rather than a raise.

## Verified, and still to verify on real hardware

Verified in isolation (scratch HOME, `OPENCODE_TEST_MANAGED_CONFIG_DIR`, never the real system
dirs): the managed reference loads on opencode 1.18.34, including a percent-encoded path with a
space and over an existing managed config; the per-home plugin loads on 1.18.34 and 2.0.24. Still
to verify by a human: a real `sudo` push on a multi-user Mac and on a Linux box, the real
`/Library/Application Support/opencode` managed reference, and that the OpenCode desktop app picks
the plugin up after a restart.
