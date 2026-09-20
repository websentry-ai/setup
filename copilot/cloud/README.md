# Copilot cloud agent

Copilot's cloud agent runs on GitHub's machines, where the installed hook does not
exist. It reads hooks only from `.github/hooks/*.json` on a repository's **default
branch**, so both files below are committed to each repository we want covered.

## Install

Copy both files into the repository and merge to the default branch:

```
copilot/cloud/unbound.json  ->  .github/hooks/unbound.json
copilot/cloud/unbound.sh    ->  .github/hooks/unbound.sh
```

Then, once per GitHub organization:

| Setting | Value |
|---|---|
| Org secret (Settings -> Secrets and variables -> Agents) | `UNBOUND_COPILOT_API_KEY` |
| Org secret | `UNBOUND_GATEWAY_URL` |
| Allowlist (Settings -> Copilot -> Internet access) | the gateway host |

Without the allowlist entry the sandbox cannot reach us, and GitHub posts a firewall
warning on the agent's pull request.

Use a dedicated application's API key, not one shared with devices: every cloud
session attributes to the application that key belongs to.

## Notes

- `unbound.sh` exits immediately on machines that already have the hook installed —
  Copilot CLI reads this config too, and both would report the same turn.
- The hook is fetched at session start rather than vendored, so repositories carry
  twenty lines instead of five thousand.
