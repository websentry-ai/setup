# Copilot cloud agent

Copilot's cloud agent runs on GitHub's machines, where the installed hook does not exist. It
reads hooks only from `.github/hooks/*.json` on a repository's **default branch**, so both
files below are committed to each repository we want covered.

## Install

Copy the config in, and **stamp the release commit** into the loader as you copy it —
`unbound.sh` ships with `__UNBOUND_HOOK_REF__` as a placeholder and refuses to run until
it holds a commit sha:

```bash
mkdir -p .github/hooks
cp copilot/cloud/unbound.json .github/hooks/unbound.json
sed "s/__UNBOUND_HOOK_REF__/$(git rev-parse HEAD)/" \
  copilot/cloud/unbound.sh > .github/hooks/unbound.sh
```

Stamping on the way in rather than editing in place keeps this one command portable
across BSD and GNU `sed`.

The ref is pinned rather than tracking `main` on purpose: the hook runs in a sandbox holding
the organization API key, so the bytes it executes must be immutable and reviewed. Set
`UNBOUND_HOOK_SHA256` as well to have the digest checked before the hook runs. Merge both
files to the default branch.

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

## Notes

- `unbound.sh` exits immediately on machines that already have the hook installed — Copilot
  CLI reads this config too, and both would report the same turn.
- The hook is fetched at session start rather than vendored, so repositories carry thirty
  lines instead of five thousand.
- Upgrading the hook means restamping the ref in each repository. That is the cost of
  pinning, and it is deliberate.
