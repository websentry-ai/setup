# Unbound plugin for opencode

`opencode/setup.py` installs the Unbound plugin into [opencode](https://opencode.ai)'s plugin
directory, so that tool calls, MCP calls, prompts and user shell commands in an opencode session
are checked against your organisation's Unbound policies. You do not normally run it by hand:
`unbound setup opencode` downloads and runs it for you.

```bash
npm install -g unbound-cli
unbound login --api-key <your key>
unbound setup opencode
# then: restart opencode (quit and relaunch the OpenCode desktop app)
```

Two entry points, both stdlib-only Python:

| Script | Scope | Runs as | Reports |
|---|---|---|---|
| `opencode/setup.py` | the current user | you | `install_mode: "user"` |
| `opencode/mdm/setup.py` | every real user on the device | root | `install_mode: "mdm"` |

The MDM variant has its own operator runbook: [`opencode/mdm/README.md`](mdm/README.md).
Everything below describes the per-user installer unless it says otherwise. The scope of the
plugin itself (what it enforces, records and cannot see) is documented in
[`hooks-ts/docs/OPENCODE.md`](../hooks-ts/docs/OPENCODE.md); this page quotes it.

---

## What it installs, and where

```
<config dir>/plugins/unbound.js                 0644   the plugin (one ESM bundle, both opencode lines)
<config dir>/plugins/unbound.js.sha256                 what --clear and a human can check
<config dir>/plugins/package.json                      {"type":"module"}, only in the case below
<config dir>/plugins/.unbound-installed.json           lists the files above that were not always ours
```

`<config dir>` is resolved by exactly the rule the plugin uses
(`hooks-ts/packages/opencode/src/profile.ts`), so the installer and the plugin can never disagree:

```
${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-~/.config}/opencode}
```

| Environment | Installs under | Why |
|---|---|---|
| nothing set | `~/.config/opencode/plugins/unbound.js` | the default, **on macOS too**: opencode uses xdg-basedir, which never answers `~/Library` |
| `OPENCODE_CONFIG_DIR` absolute (or `~/…`) | `$OPENCODE_CONFIG_DIR/plugins/unbound.js` | on opencode 2.x this variable **replaces** the XDG dir (spike V2-7), so the plugin must be there |
| `XDG_CONFIG_HOME` absolute | `$XDG_CONFIG_HOME/opencode/plugins/unbound.js` | opencode follows it |
| a relative value in either | the next rule down | never resolved against the current directory |

When the plugin went to a relocated directory the installer says so: opencode must see the same
variable at run time, or it will not load the plugin.

opencode loads every `*.js` / `*.ts` in `plugins/` (and in the legacy `plugin/`), so no opencode
config file is needed and **none is written**: `opencode.json`, `opencode.jsonc` and `tui.json`
stay byte-identical. A `plugin` entry in them that mentions unbound would load a second copy; the
installer warns about it and leaves the edit to you.

### Stray copies

Older or hand-placed copies of Unbound's plugin at `plugin/unbound.js`, `plugins/unbound.ts` or
`plugin/unbound.ts` would load beside the new one. They are removed, but only when the file is
recognised as Unbound's bundle (its banner). Other plugins are never touched.

### The ESM `package.json` rule

The bundle is an ES module. Under Bun (the opencode CLI) it loads as is. Under a plain Node host,
a `.js` file is CommonJS when the nearest `package.json` says so, and then it fails to import
(spike V1-4). So:

- an existing `plugins/package.json` is never created over or modified;
- if `plugins/` holds any other plugin file, nothing is created and a note is printed: a module
  type flip could break someone else's plugin;
- otherwise `plugins/package.json` = `{"type":"module"}` is created and recorded in
  `.unbound-installed.json`, so `--clear` removes it only if this installer created it and it is
  unchanged.

## The key

The plugin resolves its key in this order: `UNBOUND_OPENCODE_API_KEY`, then `UNBOUND_API_KEY`, then
`api_key` in `~/.unbound/config.json`, else it stays inactive (one notice per project, and it looks
again about every 30 s). The per-user installer merges the key and the tenant URLs into
`~/.unbound/config.json` (read, merge, atomic write; the file's other fields survive). A
**symlinked** `config.json` is refused, because the plugin treats a link as absent and would stay
silently inactive. The MDM installer additionally exports `UNBOUND_OPENCODE_API_KEY` in each
user's shell profile.

## Restart, remote servers and the desktop app

- opencode loads plugins at startup: **restart opencode** (quit and relaunch the OpenCode desktop
  app) after an install, an update or a `--clear`.
- Plugins run where the opencode **server** runs. With `opencode serve`, `opencode attach` or the
  desktop app's background service on another machine, run this setup on the machine where the
  server runs; a client that attaches remotely is covered only if that server has the plugin.

## What is enforced

**opencode 1.18.x (v1 line, the `server` entry):**

- model-issued shell and file tools (`bash`, `read`, `write`, `edit`, `grep`, `glob`, `lsp`,
  `apply_patch`), checked before they run; the model gets `Blocked by Unbound policy: <reason>`;
- MCP tool calls, attributed to their server;
- tool calls inside subagents;
- root-session user prompts, before they are persisted or sent to the model;
- a user `!cmd`, checked like a model `bash` call (with the caveats in `OPENCODE.md`);
- an approval verdict blocks with its own sentence (v1 has no native approval prompt).

**OpenCode 2.x (desktop / CLI 2.0.x, the `setup` entry): enforced.** Tool calls (through
opencode's permission hook), MCP tool calls, user prompts (a blocked prompt is replaced with a
block notice) and the user shell are checked, and an approval verdict uses OpenCode's native
approval prompt. Account identity on 2.x is provider-level only. The same bundle serves both lines.

Tool results are recorded hash-only, and one turn log per turn is posted. An unreachable gateway
**fails open** (a bounded 20 s check, then a breaker), except for orgs configured to fail closed.

## What is not hooked

| Surface | Status |
|---|---|
| `` !`cmd` `` inside custom slash-command templates | not hooked: template shell expansion does not go through a hook the plugin can block |
| the integrated terminal (PTY) | not hooked: commands typed there are invisible to plugins |
| processes opencode starts from config (MCP servers, LSP servers, formatters) | not hooked: they are spawned from configuration; the MCP *tool calls* are enforced |
| remote `opencode attach` clients | covered only through the server they attach to (see above) |
| `webfetch`, `websearch`, `skill`, `question` | not sent: the server has no evaluation path for them |
| tool-output content (DLP) | out of scope: results are recorded hash-only |

## Bypasses: this is advisory control, not tamper resistance

| Switch | Effect |
|---|---|
| `opencode --pure` / `OPENCODE_PURE=1` | plugins are not loaded at all; nothing is enforced or recorded (spike V1-10) |
| `XDG_CONFIG_HOME`, `HOME` or `OPENCODE_CONFIG_DIR` pointing elsewhere | opencode reads plugins from a directory this installer did not write |
| `OPENCODE_PERMISSION` | changes opencode's own permission rules (for example turning its prompts off); Unbound checks still run, but opencode's own second line of defence is gone |
| project plugins from a cloned repo (`.opencode/plugins/`) | load in the same process and can change tool arguments after the check (detected and reported as `args_changed_after_check`) |
| deleting or editing `plugins/unbound.js` | it is a file in the user's own home |

What survives a bypass is visibility: the device still reports which tools are installed. The
MDM installer adds a managed `opencode.json` reference on opencode 1.x (see
[`opencode/mdm/README.md`](mdm/README.md)), which a user cannot remove without root, but
`--pure` skips that too.

## Integrity: what the sidecar does and does not prove

The artifact is fetched from `raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/opencode/index.js`
together with the committed `opencode/index.js.sha256`. Nothing is written until the downloaded
bytes match it; on any mismatch, a missing or malformed sidecar, nothing is written and an
existing install stays byte-identical. The publish is a sibling temp file plus an atomic rename,
never a truncate in place.

The sidecar comes from the same origin, over the same TLS, from the same ref as the artifact. It
catches truncation, corruption and a stale-vs-fresh mismatch, and it gives the backend an honest
`hook_hash`. It is **not** a supply-chain control: anyone who could replace the artifact could
replace the sidecar in the same commit.

## What gets reported

One best-effort `POST /api/v1/setup/complete/` on success:

```json
{
  "tool_type": "opencode",
  "install_state": "fresh",
  "serial_number": "<this device's serial>",
  "hook_hash": "<sha256 of the unbound.js actually written>",
  "install_mode": "user"
}
```

`install_state` is read before the write, so a second run reports `persisted`. The key travels in
a `0600` temporary header file, never on the command line. A failed report prints one line and the
install still succeeds: the plugin enforces from the key on the machine, not from the report.

## `--clear`

```bash
unbound setup opencode --clear
```

removes `plugins/unbound.js`, `plugins/unbound.js.sha256`, and `plugins/package.json` only when
the marker says this installer created it and it is still exactly `{"type":"module"}`. It leaves
the directory and every other file in it, never opens `~/.unbound/config.json` (its `api_key` is
shared with the other Unbound tools), needs no key, makes no network call and reports nothing:
`install_state` has no uninstall value. Restart opencode afterwards.

## Preflight

The installer needs python3 3.8 or newer. A missing `opencode` on `PATH` only warns: the OpenCode
desktop app puts no CLI on `PATH`, and installing before opencode is a supported order. When
`HTTPS_PROXY` is set it notes that the plugin calls Unbound through opencode's own runtime fetch,
so a corporate proxy CA must be trusted by that runtime (for example `NODE_EXTRA_CA_CERTS`).

## Files

| Path | What it is |
|---|---|
| `opencode/setup.py` | the per-user installer (this document) |
| `opencode/mdm/setup.py` | the root, all-users installer |
| `opencode/mdm/README.md` | the MDM operator runbook |
| `opencode/index.js` | the built plugin bundle, **generated, do not edit** (source: `hooks-ts/packages/opencode`) |
| `opencode/index.js.sha256` | the integrity sidecar, gated against a fresh build in CI |
| `hooks-ts/docs/OPENCODE.md` | the plugin's scope, gaps, bypasses and signals |
| `hooks-ts/docs/SMOKE.md` | the smoke recipes, including the isolated install smoke |
