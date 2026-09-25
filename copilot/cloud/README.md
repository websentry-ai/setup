# Copilot Cloud Agent Setup

The cloud agent runs on GitHub's machines, where the installed hook does not exist. It
reads hooks only from `.github/hooks/*.json` on a repository's **default branch**, so
these two files are committed to each repository we cover.

## Usage

Run from a checkout of this repo, inside the target repository. The order matters: the
config pins the loader's digest, and the loader is stamped first.

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

Merge both files to the default branch. Re-run all three steps whenever either file
changes — a stale `__UNBOUND_LOADER_SHA__` denies every `preToolUse`.

## Once per GitHub organization

| Setting | Value |
|---|---|
| Agents secret (Settings -> Secrets and variables -> Agents) | `UNBOUND_COPILOT_API_KEY` |
| Agents secret | `UNBOUND_GATEWAY_URL` |
| Agents secret, recommended | `UNBOUND_HOOK_SHA256` — sha256 of `copilot/hooks/unbound.py` at the stamped ref |
| Allowlist (Settings -> Copilot -> Internet access) | the gateway host, and `raw.githubusercontent.com` |

Both hosts matter: without the gateway a session reports nothing, and without
`raw.githubusercontent.com` the hook never loads — which denies every `preToolUse` rather
than silently permitting it.

Use a dedicated application's API key, not one shared with devices. Every cloud session
attributes to that application, reports `agent_surface: cloud`, and is deliberately kept
off the key owner's per-user budget.

**`UNBOUND_COPILOT_API_KEY` is readable by the agent, not just by the hook.** GitHub
exposes Agents secrets "as environment variables in its development environment, so they
can be used by scripts and tools that Copilot runs" — there is no hook-only channel. A
prompt-injected agent can therefore read the key, send it to any allowlisted host, and
call the gateway directly with forged telemetry or pre-tool requests. A dedicated
application limits the blast radius; it does not prevent the leak. Closing it needs
short-lived per-session tokens, or server-side validation of `github.session` and `repo`.

Without `UNBOUND_HOOK_SHA256` the hook is fetched into memory on every event and never
cached, so the trust root is TLS to the pinned commit alone.
