# Unbound extension for Pi Coding Agent

`pi/setup.py` installs the Unbound extension into [pi](https://pi.dev)'s extension directory so
that every tool call, prompt and turn in a pi session is checked against your organisation's
Unbound policies. You do not normally run it by hand — `unbound setup pi` downloads and runs it
for you.

```bash
npm install -g unbound-cli
unbound login --api-key <your key>
unbound setup pi
# then: start a new pi session
```

Two entry points, both stdlib-only Python:

| Script | Scope | Runs as | Reports |
|---|---|---|---|
| `pi/setup.py` | the current user | you | `install_mode: "user"` |
| `pi/mdm/setup.py` | every real user on the device | root | `install_mode: "mdm"` |

The MDM variant has its own operator runbook — see [`pi/mdm/README.md`](mdm/README.md). Everything
below describes the per-user installer unless it says otherwise.

---

## What it installs, and where

One file: **`index.js`**, plus a small `index.js.sha256` sidecar next to it so `--clear` knows what
it wrote.

```
<agent-dir>/extensions/unbound/index.js         0644
<agent-dir>/extensions/unbound/index.js.sha256
```

`<agent-dir>` is resolved exactly the way the extension itself resolves it
(`hooks-ts/packages/core/src/cache.ts`), because an installer that disagrees with the extension
writes a real file into a directory pi never reads — and then reports success. The rule is
`PI_CODING_AGENT_DIR`, with four cases:

| `PI_CODING_AGENT_DIR` | Installs under | Why |
|---|---|---|
| unset (or set to whitespace) | `~/.pi/agent` | the default, `PI_AGENT_DIR_SEGMENTS = [".pi","agent"]` |
| an **absolute** path | that path, as-is | you relocated your agent dir; we follow |
| `~` or `~/something` | your home, or `~/something` | tilde expanded against **your** home |
| a **relative** path (`pitest`, `./x`, `../x`) | `~/.pi/agent` | pi never resolves it against the current directory, so neither do we |

If there is no safe absolute base at all (an empty or relative `HOME`), the installer refuses
rather than guessing a path.

It writes nothing else. It does not touch other extension directories, it does not modify your pi
configuration, and it does not install or update pi itself.

## Where the key goes, and the one config shape that is refused

The key is merged into `~/.unbound/config.json` — the shared identity store `unbound-cli` and five
other tools read — rather than written over it, so your email, org and per-tool URLs survive.

If `~/.unbound/config.json` is a **symlink** (a dotfiles repository, typically), the installer
**refuses and exits `1` without writing**. This is not fussiness: the extension reads that path
with `lstat` and treats a link as absent (`hooks-ts/packages/core/src/safeRead.ts`, which refuses a
link so a `config.json` replaced by a FIFO cannot wedge pi on session start). A key written through
the link would therefore never be read — the extension would install and then be silently inactive,
with setup reporting success — and the key would land in your dotfiles repo as a bonus. Replace the
link with a regular file and re-run, or export `UNBOUND_PI_API_KEY`, which the extension prefers
over the config file anyway.

## The `index.ts` shadow rule

**pi resolves `index.ts` before `index.js` in the same extension directory.** A leftover
`index.ts` in `extensions/unbound/` therefore wins silently: pi starts with no error, loads the
wrong file, and no policy check ever fires. This is the single highest-severity failure mode in
the install path, so the installer handles it for you:

- an existing **`index.ts`** is **moved aside** to `index.ts.unbound-disabled` — never deleted, it
  may be your own work — and a loud warning prints:

  ```
  ⚠️  Found index.ts, which would shadow index.js -- pi resolves it first.
     Moved it to index.ts.unbound-disabled; it was not deleted. Nothing else changed.
  ```

  If `index.ts.unbound-disabled` already exists, the next free name (`…disabled.1`) is used, so an
  earlier rescued file is never overwritten.
- an existing **`package.json`** in the same directory warns (it can change module resolution) and
  the install continues; the file is left byte-identical.
- `--clear` restores nothing, because it never wrote the `.ts`. If you want your `index.ts` back,
  rename it yourself.

## Integrity: what the sidecar does and does not prove

The artifact is fetched from `raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/pi/index.js`
together with a committed `pi/index.js.sha256`. The installer compares the digest of the downloaded
bytes against that sidecar and **refuses to write on any mismatch** — as well as on a missing
sidecar, a malformed one, or a sidecar that names a different file. On refusal nothing is written
and an existing install is left byte-identical. After a successful write the file on disk is
re-hashed and compared again, so the digest that gets reported is provably the bytes on disk.

**Be clear-eyed about what that buys.** The sidecar comes from the same origin, over the same TLS
connection, from the same git ref as the artifact. It detects **truncation, corruption, a partial
download, and a stale-vs-fresh mismatch**. It is **not a supply-chain control**: anyone who can
change `pi/index.js` on that ref can change `pi/index.js.sha256` in the same commit.

The repo's stronger precedent is `mdm/onboard.sh.tmpl`, which embeds the expected `PKG_SHA256`
inside the *fetching* script, so the digest and the artifact travel by different paths. That is
genuinely better, and it is not used here for one concrete reason: it needs a two-commit publish
(commit the artifact, then commit its hash into the fetcher), which the existing `hooks-ts.yml`
`cmp` drift gate cannot express. CI does gate the sidecar against a fresh build, so the sidecar
cannot silently rot — but it is a consistency guard, not an attestation. Said plainly rather than
implied stronger.

## What gets reported

On a successful install the installer makes one best-effort `POST /api/v1/setup/complete/`:

```json
{
  "tool_type": "pi",
  "install_state": "fresh",
  "serial_number": "<this device's serial>",
  "hook_hash": "<sha256 of the index.js actually written>",
  "install_mode": "user"
}
```

- `install_state` is read **before** the write, so a second run reports `persisted`.
- `managed` is deliberately absent — it gates tamper counting on the backend, and pi has no managed
  configuration to compare against.
- The key travels in a `0600` temporary header file, never on the command line, and the body goes
  over stdin.
- **Reporting is best-effort.** A 4xx or a transport failure prints one line and the install still
  succeeds:

  ```
  ⚠️  Could not report this install to the backend. Install-state reporting is
     best-effort; the extension is installed and enforces regardless.
  ```

  The extension enforces from the key on the machine, not from the report, so a failed report costs
  you a console row and nothing else.

## What the extension sends at runtime

That report is the installer's. Once installed, the extension itself sends the following, and only
with a key on the machine (no key, or a key the gateway rejected, means nothing is sent or captured):

- **Every evaluated tool call** (`POST /v1/hooks/pretool`) carries the current turn's prompt as
  `messages[0].content`, capped at 8 KB with both ends kept. The gateway writes its block/warn row from
  that field, so a blocked command's row shows what was being asked.
- **MCP calls made through `pi-mcp-adapter`** (the `mcp` proxy tool, a `mcp__<server>` namespace tool,
  or a direct `<server>_<tool>` tool) are resolved to the server and tool the adapter will run and sent
  to the gateway's MCP policy path as `mcp__<server>__<tool>`, with the call's arguments (capped at
  16 KB) and the server's `url`, or `command` + `args`, read from the adapter's config files. The
  server's `env`, `headers`, bearer tokens and OAuth settings are never read into the request.
  A call that cannot be attributed to exactly one server and tool is not checked (as before).
- **The turn log** (`POST /v1/hooks/pi`) carries each tool's text output, capped at 8 KB per result
  (head and tail kept) and 128 KB per turn, with bearer tokens and the Unbound key redacted, next to a
  sha256 and a byte count. Image output is never sent; it is represented by its hash and size only.
  This is what lets tool-output DLP and MCP output audit run for pi (where the org has them enabled).
- **A typed `!cmd`** is logged as its own one-call row the moment it is checked, not folded into the
  next agent turn.

Known gaps:

- `mcpScript` (a script that can call several MCP tools) is not enforced. The follow-up is the
  adapter's own `pi-mcp-adapter:tool-approval-request` broker event.
- There is no unknown-server scan dispatch. In an org that blocks unsanctioned MCP servers, a server no
  device has scanned yet is reported as "being scanned" for up to an hour and is not resolved by pi.
- Local-script stdio servers (`node ./server.js`) get no `scriptHash`, so their fingerprint is null.
- The adapter's config imports, plugins and opt-in ancestor files are not read; only the six standard
  config files are.
- With a cold or missing `mcp-cache.json`, only calls whose name starts with a configured server's
  prefix can be resolved. Anything unresolved runs unenforced, which is the behaviour before this
  change.
- Allowed pi MCP calls do not show up in MCP usage analytics yet; that needs a separate
  `ai-gateway-data` change to parse pi turn logs. Blocked and warned MCP calls do appear, through the
  gateway's block row.

## `--clear` removes the extension and reports **nothing**

```bash
unbound setup pi --clear
```

removes exactly `index.js` and `index.js.sha256` from the resolved extension directory, prints a
per-file `cleared` / `not_found`, leaves the directory itself and every file it did not write
(including a live `index.ts` and any `.unbound-disabled` file), needs no API key, and makes **no
network call at all**. It never opens `~/.unbound/config.json` — that `api_key` is shared with
Cursor, Claude Code, Codex, Copilot and Augment Code, so removing pi must not log those tools out.

**`--clear` sends nothing to the backend, and that is deliberate.** Two facts drive it:

1. **No installer in this repository posts on clear.** Every one of the 20 `notify_setup_complete`
   call sites in the repo is on an install-success path; `clear_setup()` returns before any POST in
   all of them.
2. **The backend has no uninstall state to report.** `install_state` is an install-time enum —
   `fresh`, `persisted`, `tampered` — with no `uninstalled`/`removed`/`cleared` value, and
   `POST /setup/complete/` has no uninstall branch. A fabricated value would be dropped by the
   handler, which is worse than silence: a POST that looks like it works and does nothing.

So "pi reports its uninstall the way the other tools do" means **it stays quiet**, and the console
keeps showing the last install until something else changes it. If a real uninstall signal is
wanted, that is a backend change (a new `install_state` value, or an uninstall endpoint) and a
future piece of work — not something this installer can fake.

## Preflight

The installer warns, and never blocks, if pi is missing from `PATH` or older than the tested
version (`0.87.1`). pi installs to `~/.local/bin`, not an npm global prefix. An unparseable
`pi --version`, or a pi that cannot be executed at all, is not an error — you may be installing
ahead of pi.

## All-users / MDM install

`pi/mdm/setup.py`, run as root, covers every real user on the device in one pass: it enumerates
homes, verifies the artifact **once** before touching anything, and writes into each home only
behind a real `fork` + `setuid` privilege drop with `O_NOFOLLOW` opens. It reports once per device
with `install_mode: "mdm"`. Two constraints matter to an operator:

- it installs to **`<home>/.pi/agent` only** — `PI_CODING_AGENT_DIR` lives in the target user's
  shell environment, which root cannot read, and reading root's own copy would redirect every
  user's install into one shared directory. A user who has relocated their agent directory needs
  the per-user `unbound setup pi`.
- it is **not** registered in `mdm/onboard.py`'s `TOOLS` list, so the Jamf bootstrap does not run
  it automatically yet.

Full details, including both deliberate key-placement divergences from the Augment analog, are in
[`pi/mdm/README.md`](mdm/README.md).

## Limitation: this is advisory control, not tamper resistance

**pi has no managed or enterprise settings file.** There is nowhere for an administrator to pin
"extensions are mandatory", so the enforcement this installer sets up can be bypassed by the person
sitting at the machine, three ways:

| Bypass | Effect |
|---|---|
| `pi --no-extensions` | pi loads no extensions at all, including this one — verified: the mock API logs no request |
| a redirected `PI_CODING_AGENT_DIR` | pi reads a different directory than the one we installed into |
| an SDK embedder passing `noExtensions` | a program embedding pi can decline extensions outright |

Deleting or editing `index.js` works too, for the same reason: it is a file in the user's own home.

This is **advisory control over a machine whose user is an administrator of it**, and it is worth
stating plainly rather than discovering later. What does survive a bypass is *visibility*:
`coding-discovery-tool` reports that pi is **installed** on a device independently of this
extension, so a bypassing machine still shows up as "has pi". The narrower finding — "has pi, but
no Unbound extension loaded" — is not implemented today and is tracked as backlog.

One structural consequence is worth naming for completeness: the extension fails **open** on
timeout or error (a bounded fail-open, then a circuit breaker). A device that cannot reach the
gateway keeps working rather than blocking every command. That is an existing, deliberate property
of the extension, not something the installer changes.

## Files

| Path | What it is |
|---|---|
| `pi/setup.py` | the per-user installer (this document) |
| `pi/mdm/setup.py` | the root, all-users installer |
| `pi/mdm/README.md` | the MDM operator runbook |
| `pi/index.js` | the built extension bundle — **generated, do not edit** (source: `hooks-ts/`) |
| `pi/index.js.sha256` | the integrity sidecar, gated against a fresh build by `.github/workflows/hooks-ts.yml` |
| `hooks-ts/docs/SMOKE.md` | the manual smoke recipes, including the Phase 10 install rows P1–P6 |
