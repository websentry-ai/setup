# Copilot cloud agent

Copilot's cloud agent runs on GitHub's machines, where the installed hook does not exist. It
reads hooks only from `.github/hooks/*.json` on a repository's **default branch**, so both
files below are committed to each repository we want covered.

## Install

Two placeholders get stamped, and the order matters: the loader's digest covers the ref
already written into it.

```bash
mkdir -p .github/hooks

# 1. Stamp the release commit into the loader.
sed "s/__UNBOUND_HOOK_REF__/$(git rev-parse HEAD)/" \
  copilot/cloud/unbound.sh > .github/hooks/unbound.sh

# 2. Digest the stamped loader.
LOADER_SHA=$( { sha256sum .github/hooks/unbound.sh 2>/dev/null \
  || shasum -a 256 .github/hooks/unbound.sh; } | cut -d' ' -f1 )

# 3. Stamp that digest into the config.
sed "s/__UNBOUND_LOADER_SHA__/$LOADER_SHA/" \
  copilot/cloud/unbound.json > .github/hooks/unbound.json
```

Stamping on the way in rather than editing in place keeps these portable across BSD and
GNU `sed`, and leaves no second copy of a placeholder for a later `sed` to rewrite.

The ref is pinned rather than tracking `main` on purpose: the hook runs in a sandbox holding
the organization API key, so the bytes it executes must be immutable and reviewed. Set
`UNBOUND_HOOK_SHA256` as well to have the fetched hook's digest checked before it runs.
Merge both files to the default branch.

Then, once per GitHub organization:

| Setting | Value |
|---|---|
| Org secret (Settings -> Secrets and variables -> Agents) | `UNBOUND_COPILOT_API_KEY` |
| Org secret | `UNBOUND_GATEWAY_URL` |
| Allowlist (Settings -> Copilot -> Internet access) | the gateway host, and `raw.githubusercontent.com` |

Both hosts matter. Without the gateway the session reports nothing; without
`raw.githubusercontent.com` the hook never loads, and a `preToolUse` that cannot load its
evaluator denies the tool call rather than silently permitting it.

Use a dedicated application's API key, not one shared with devices: every cloud session
attributes to the application that key belongs to, and its spend is deliberately kept off
the key owner's per-user budget.

These sessions report `agent_surface: cloud`, alongside the `cli` and `vscode` surfaces
the installed hook reports.

## What the agent can and cannot change

The agent and the hook run as the same user, so the agent can write any file the hook
reads. Only two things are outside its reach, and both are load-bearing:

- **`unbound.json`** — GitHub reads hook config from the default branch, never from the
  checkout, so nothing the agent writes in its workspace is seen.
- **The bytes that actually run** — pinned by digest from inside that config.
  `unbound.sh` *does* live in the checkout and the agent can rewrite it, so the config
  checks its digest before running it. A rewritten loader fails the check, and the
  command exits non-zero: `preToolUse` treats that as a deny, and every other event
  simply records a failure. The loader in turn pins the hook it fetches to a commit, and
  verifies `UNBOUND_HOOK_SHA256` when one is set.

Each link **verifies and runs one snapshot**, never a path twice. The config reads the
loader into a variable, hashes that variable and runs it with `bash -c`; the loader reads
the hook into a variable, hashes that variable and hands it to the interpreter on a file
descriptor. Hashing a file and then passing its *name* to the next program would leave a
window to swap it in between — and since the agent shares our uid, no file mode closes
that window. A shell variable in a running process is the one thing it cannot reach.

(The hook goes over a descriptor rather than `python3 -c` because it is ~320KB and Linux
caps a single argument at 128KB. Stdin stays free for the event payload.)

Two things make that chain hold in practice:

- **The hook runs under `python3 -I`.** A script's own directory goes on `sys.path` ahead
  of the standard library, and here that directory is `/tmp` — so a planted `/tmp/json.py`
  would be imported by the verified hook and the digests above would prove nothing.
  Isolated mode drops the script directory, `PYTHONPATH` and user site-packages.
- **`PATH` starts at `/usr/bin:/bin`** in both the config and the loader, so the
  `sha256sum` doing the verifying cannot itself be shadowed.
- **Every `curl` runs with `-q`**, in the loader and in the hook's own calls to the
  gateway. Without it curl reads `~/.curlrc`, and one `insecure` or `resolve` line there
  would point the pre-tool check — the call that decides allow or deny — at a server the
  agent controls. Cloud only: on a laptop that same file is how a corporate proxy is
  configured.

Everything else the hook keeps under `/tmp` is writable by the agent. The rule is not that
those files are hardened individually — it is that **sandbox state is never allowed to
produce an allow**:

- the policy cache is not read in the cloud, so a planted one cannot send a write down
  the no-gateway short-circuit;
- approval markers are ignored, so a planted one cannot start a poll that outlives the
  hook timeout;
- the audit log is read from its tail past a size cap, so bloating it cannot stall
  `preToolUse` into its fail-open timeout.

The audit log, caches and watermarks remain agent-writable as telemetry. That is accepted:
losing or forging telemetry is not the same as forging a decision.

Two residual limits worth stating plainly:

- With `UNBOUND_HOOK_SHA256` unset, nothing verifies the fetched hook and the trust root
  is only TLS to the pinned commit. The hook is then never written to disk at all — it is
  fetched straight into memory and executed from there, because an unverifiable cache is a
  file the agent can swap for no benefit. **Set the digest for production installs**; with
  one, the `/tmp` cache is kept and re-verified on every event.
- `github.actor` is parsed from the co-author trailer on commits the agent itself writes,
  so it is provenance, not authenticated identity. GitHub exposes no actor to the
  sandbox. Treat it as unverified wherever it is displayed.

## Notes

- Cloud sessions only, and the check is the **first thing the config does** — before the
  digest gate. Copilot CLI reads this config on laptops too, where a managed install
  already reports the turn, and where that install may be the binary rather than
  `~/.copilot/hooks/unbound.py`, so the file's presence is the wrong thing to test. Two
  things would go wrong if the laptop got as far as the gate: a checkout whose
  `unbound.sh` differs from the default branch would fail the digest and deny every tool
  call, and a laptop with no install at all would have telemetry switched on by cloning
  a repository.
- Cloud sessions send no `device_serial`: an ephemeral VM's machine-id is not a device.
  The `github` block is their provenance.
- Changing `unbound.sh` means restamping `__UNBOUND_LOADER_SHA__` too, since the config
  pins its digest.
- The hook is fetched at session start rather than vendored, so repositories carry thirty
  lines instead of five thousand.
- Upgrading the hook means restamping the ref in each repository. That is the cost of
  pinning, and it is deliberate.
