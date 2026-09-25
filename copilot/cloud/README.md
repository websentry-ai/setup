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

Everything else the hook keeps under `/tmp` — the audit log, caches, approval markers —
is writable by the agent and is not treated as trusted. Hardening those individually is
whack-a-mole; the digest chain above is the boundary that matters.

Two residual limits worth stating plainly:

- With `UNBOUND_HOOK_SHA256` unset the fetched hook is re-downloaded every event rather
  than reused from `/tmp`, but nothing verifies it. **Set it for production installs.**
- `github.actor` is parsed from the co-author trailer on commits the agent itself writes,
  so it is provenance, not authenticated identity. GitHub exposes no actor to the
  sandbox. Treat it as unverified wherever it is displayed.

## Notes

- `unbound.sh` exits immediately on machines that already have the hook installed — Copilot
  CLI reads this config too, and both would report the same turn.
- Changing `unbound.sh` means restamping `__UNBOUND_LOADER_SHA__` too, since the config
  pins its digest.
- The hook is fetched at session start rather than vendored, so repositories carry thirty
  lines instead of five thousand.
- Upgrading the hook means restamping the ref in each repository. That is the cost of
  pinning, and it is deliberate.
