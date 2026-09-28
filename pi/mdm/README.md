# Pi Coding Agent — MDM / all-users installer

`setup.py` in this directory installs the Unbound extension for the Pi Coding Agent for
**every real user on a device**, in one root run, from an MDM (Jamf and friends).

## Read this first: what this does and does not buy you

pi has **no managed or enterprise settings file**. There is no `/etc/pi/settings.json`
equivalent, no MDM-only configuration domain, and no way to mark an extension as
non-removable. That means all three of these bypass the extension entirely, and nothing in
this script can prevent any of them:

- `pi --no-extensions` — the user simply starts pi without extensions.
- `PI_CODING_AGENT_DIR` pointed at another directory — pi then looks for extensions
  somewhere this installer did not write.
- an SDK embedder passing `noExtensions` — a program embedding pi opts out in code.

So this is **advisory control over a machine whose user is an administrator of it**, not
tamper resistance. Deploy it to get coverage by default, not to get a guarantee. What you
still keep is *visibility*: `coding-discovery-tool` reports that pi is **installed** on a
device regardless, so a bypassing machine remains visible as "has pi". The narrower
"has pi but no Unbound extension" finding is backlog, not shipped.

This is recorded in the same words in the installer's own header, in `hooks-ts/README.md`
and in `hooks-ts/docs/SPIKES.md`.

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

`--api-key` takes an **admin** application key: it is exchanged once per device for this
org's pi application key and is never written to disk. It never appears on a `curl` argv
either — it travels in a `0600` temp header file, because `ps` and `/proc/<pid>/cmdline` are
world-readable on a multi-user host.

Root is required. Without it the script prints one line and exits `1` without touching any
home. `--debug` is redundant in practice: MDM runs always force debug logging on, the same
way the other MDM installers in this repo do.

## What lands on disk, per user

| Path | Mode | Owner |
|---|---|---|
| `<home>/.pi/agent/extensions/unbound/index.js` | `0644` | that user |
| `<home>/.pi/agent/extensions/unbound/index.js.sha256` | `0644` | that user |
| an `export UNBOUND_PI_API_KEY="…"` line in `~/.zprofile` + `~/.bash_profile` (macOS) or `~/.zshrc` + `~/.bashrc` (Linux) | group/other bits stripped (`0644` → `0600`) | that user |
| `api_key` in `<home>/.unbound/config.json`, **only when absent or previously written by this installer** | `0600` in a `0700` dir | that user |
| `pi_mdm_api_key_sha256` in the same file — the digest that marks that `api_key` as ours | `0600` in a `0700` dir | that user |

**Default agent directory only.** `PI_CODING_AGENT_DIR` belongs to the *target user's* shell
environment, which root running from an MDM cannot read. Reading root's own copy of it would
install every user's extension into one shared directory, so this installer does not look at
it at all and covers `<home>/.pi/agent` only. A user who has relocated their agent directory
is not covered by an MDM push and must run the per-user `unbound setup pi` instead.

## Key placement, and one deliberate divergence

The extension resolves its key in this order (`hooks-ts/packages/core/src/config.ts`):
`UNBOUND_PI_API_KEY` → `UNBOUND_API_KEY` → `~/.unbound/config.json` `api_key` → inactive.

Both tier 1 and tier 3 are written, because an rc export is invisible to a shell that is
already open and to a GUI-launched pi, while `config.json` is what makes the *current*
session work.

Two things differ from the `augment/hooks/mdm/setup.py` analog this script is otherwise a
port of, both called out in comments at the code:

1. **`config.json`'s `api_key` is written by ownership, not assigned.** Augment overwrites it
   unconditionally. That file is the shared identity store for `unbound-cli` and five other
   tools (Cursor, Claude Code, Codex, Copilot, Augment), so on a device where the user has run
   `unbound login`, overwriting it would silently repoint **all of them** at this device key.

   A blanket "never overwrite" was wrong in the other direction, though: the value *this
   installer* wrote on the first push is also an existing value, so after the org revoked that
   key a later push updated the rc exports and left the dead key in `config.json` — the one
   tier a GUI-launched pi and every already-open shell read. The extension went on
   authenticating with a revoked key, after a redeployment that reported success.

   So the installer records a `pi_mdm_api_key_sha256` digest beside any `api_key` it writes,
   and on a later push replaces the value only when it is absent, already equal to the key
   being installed, or matches that digest. Anything else is the user's own credential and is
   left byte-identical. **Rotating a pi application key therefore takes effect in both tiers
   on the next push.** The digest is provenance, not a secret — the key itself is in the same
   `0600` file — and no other tool reads that field.

   The tenant URL fields (`base_url`, `gateway_url`, `frontend_url`) *are* written
   unconditionally — they are configuration, not identity.
2. **The `export` value passes a charset allow-list first** (`_is_safe_env_value`). An rc
   file is executed by the user's login shell, so an unvalidated value in it is command
   injection, on every account on the device. This check is an addition, not a port.
3. **The rc file is published owner-only.** The analog writes `0644`, which is the normal
   mode for a shell profile — but this line holds a plaintext application key, and a macOS
   home directory is `0755` by default, so every other local account (including the service
   accounts this installer skips) could read the key out of `~/.zprofile`. The rewrite strips
   the group and other bits and never adds a bit the file did not have, so a profile kept at
   `0600` or `0700` is unchanged. `--clear` removes the export line but does not widen the
   mode back: the original is not recoverable, and owner-only is the safe end state.

The `UNBOUND_PI_API_KEY` variable is deliberately the pi-specific tier and never the generic
`UNBOUND_API_KEY`: writing a device key to the generic name would hand it to six other tools.

## Writing into another user's home as root

Every in-home write goes through three primitives, ported from the Augment analog:

1. **`_run_as_user`** — `fork`, then `setgroups([])` / `setgid` / `setuid` (in that order)
   before touching anything. After the drop, a symlink in the home pointing at a root-only
   path fails with `EACCES` on its own.
2. **`_repair_user_ownership`** — walks the path **one component at a time**, each opened
   `O_NOFOLLOW` relative to the previous component's descriptor (`openat`) and anchored at the
   passwd home. A whole-path `O_NOFOLLOW` only guards the *last* component, so a symlinked
   parent (`~/.pi/agent/extensions` → `/etc`) could redirect the repair outside the home; a
   component-wise walk cannot. It then `fchown`s the resulting **descriptor**, so the inode
   inspected is the inode chowned and there is no path TOCTOU. A regular file carrying extra
   hard links (`st_nlink != 1`) is refused outright. Directories are reclaimed only when root-
   or self-owned, and the home directory itself is never chowned — a deliberately root-owned
   home (an sshd `ChrootDirectory`, an admin-locked kiosk account) must survive an MDM push.
3. **The drop itself** opens `index.js` with `O_NOFOLLOW` too, and runs the `index.ts`
   shadow guard per home.

pi resolves `index.ts` **before** `index.js` in an extension directory, so one user's
leftover `.ts` silently defeats enforcement for that user: pi starts, logs no load error, and
no policy check ever fires. The guard renames it to `index.ts.unbound-disabled` — it is never
deleted, and an existing `.unbound-disabled` file is never overwritten.

One unwritable home costs that user their coverage and nothing more; the loop continues and
prints a per-user result table.

## What counts as a successful push

An account is covered only when **both** halves landed: the extension, and a key it can read
(the `UNBOUND_PI_API_KEY` export, or `api_key` in `~/.unbound/config.json` — either one is
enough). An extension with no readable key loads and enforces nothing, so a run where no
account got a key exits `1` even though every `index.js` is on disk. The extension is left in
place; removing it would be worse, and the next push repairs the key. Exiting `0` there used
to tell the MDM the device was fine, which is precisely the device that needed remediation.

## The integrity sidecar, honestly

`pi/index.js.sha256` is fetched from the same origin, over the same TLS, from the same ref as
`pi/index.js` itself. It catches a truncated or corrupt download and a stale-vs-fresh
mismatch, and it gives the backend an honest `hook_hash`. It is **not** a supply-chain
control: anyone who could replace the artifact could replace the sidecar in the same commit.

The artifact is downloaded and verified **once**, before the home loop, so a bad artifact
reaches zero homes rather than all of them.

## Reporting

Exactly one report per device run, after the loop:

```
POST /api/v1/setup/complete/
{"tool_type": "pi", "install_state": "fresh|persisted", "serial_number": "<device serial>",
 "hook_hash": "<sha256 of the installed index.js>", "install_mode": "mdm"}
```

`install_state` is read **before** any home is written, so `persisted` means "this device
already had it". A report failure prints one line and does **not** change the exit status —
the extension is installed and enforcing whether or not the backend heard about it.

This installer deliberately does **not** post the device-level
`POST /api/v1/automations/mdm/install-report/` endpoint. That is Jamf bootstrap telemetry: it
carries no `tool_type`, so a pi install reported there would never show the device as having
pi. (The ROADMAP and REQUIREMENTS text says `install-report`; that wording is wrong and is
being corrected — see `10-RESEARCH.md` §C5.)

`--clear` reports **nothing**, matching every other installer in this repo: `install_state`
is an install-time enum with no uninstall value.

## `--clear`

Removes `index.js` and `index.js.sha256` from every enumerated home, and the
`UNBOUND_PI_API_KEY` export line from every user's rc files. It leaves the extension
directory, every file in it that this installer did not write, any `index.ts` or
`index.ts.unbound-disabled`, and — deliberately — `~/.unbound/config.json` entirely alone:
its `api_key` is shared with the other Unbound tools, so removing it would log the user out
of all of them. It makes no network call. Without root it refuses cleanly (exit `1`, no
traceback).

## Not registered in `mdm/onboard.py`

`mdm/onboard.py` has a hard-coded `TOOLS` list of the MDM installers the fleet bootstrap runs
automatically. **pi is deliberately not in it**, and INST-03 does not ask for it: every added
tool lengthens every device's Jamf run, and pi's fleet penetration today is near zero. Run
this script directly from an MDM policy instead.

Follow-up if that changes: add `pi` to `mdm/onboard.py`'s `TOOLS` and re-verify the
bootstrap's total runtime budget.

## Home enumeration

| Platform | Source | Rule |
|---|---|---|
| macOS | `pwd.getpwall()` | `uid >= 500`, home exists and is a directory, home under the `Users` prefix, name not `Shared` or `Guest` |
| Linux | `pwd.getpwall()` | `uid >= 1000`, home exists and is a directory, home under the `home` prefix |
| Windows | the profile directories under `%SystemDrive%\Users` | skip `Public`, `Default`, `Default User`, `Administrator`, `All Users` |

Any failure — a broken directory service, no `pwd` module, an unrecognised platform — yields
an empty list rather than a raise, so a device run never aborts before the first home is
considered.
