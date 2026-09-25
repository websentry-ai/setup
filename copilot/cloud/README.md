# Copilot Cloud Agent Setup

Copilot's cloud agent runs on GitHub's machines, where the installed hook does not exist.
It reads hooks only from `.github/hooks/*.json` on a repository's **default branch**, so
both files go in every repository to be covered.

## Per repository

```bash
cp copilot/cloud/unbound.json .github/hooks/unbound.json
cp copilot/cloud/unbound.sh   .github/hooks/unbound.sh

# Stamp the release commit and the loader's own digest.
sed -i '' "s/__UNBOUND_HOOK_REF__/$(git rev-parse HEAD)/" .github/hooks/unbound.sh
sed -i '' "s/__UNBOUND_LOADER_SHA__/$(sha256sum .github/hooks/unbound.sh | cut -d' ' -f1)/" .github/hooks/unbound.json
```

Merge both to the default branch. The ref is pinned, not tracking `main`: the hook runs in
a sandbox holding the organization API key. A stale ref denies every `preToolUse`, so
restamp on upgrade.

## Per GitHub organization

| Setting | Value |
|---|---|
| Secret (Settings → Secrets and variables → Agents) | `UNBOUND_COPILOT_API_KEY` |
| Secret | `UNBOUND_GATEWAY_URL` |
| Allowlist (Settings → Copilot → Internet access) | the gateway host, `raw.githubusercontent.com` |

Both hosts are required. Without the gateway the session reports nothing; without
`raw.githubusercontent.com` the hook never loads and every `preToolUse` denies.

Use a dedicated application's API key, not one shared with devices: every cloud session
attributes to the application that key belongs to.

## Optional

`UNBOUND_HOOK_URL` serves the hook from a mirror, and then `UNBOUND_HOOK_SHA256` is
required — an override is not pinned to a commit.
