# Copilot Cloud Agent Setup

Copilot's cloud agent runs on GitHub's machines, where the installed hook does not exist.
It reads hooks only from `.github/hooks/*.json` on a repository's **default branch**, so
both files go in every repository to be covered.

## Per repository

Stamp as you copy: the loader takes the release commit, then the config takes the digest
of the stamped loader. `sed -i` is not portable, so nothing is edited in place.

```bash
mkdir -p .github/hooks

sed "s/__UNBOUND_HOOK_REF__/$(git rev-parse HEAD)/" \
  copilot/cloud/unbound.sh > .github/hooks/unbound.sh

LOADER_SHA=$( { sha256sum .github/hooks/unbound.sh 2>/dev/null \
  || shasum -a 256 .github/hooks/unbound.sh; } | cut -d' ' -f1 )

sed "s/__UNBOUND_LOADER_SHA__/$LOADER_SHA/" \
  copilot/cloud/unbound.json > .github/hooks/unbound.json
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

## Trust model

Three limits are known and accepted. Each needs gateway-side work to close, not a hook change.

**`UNBOUND_COPILOT_API_KEY` is readable by the agent, not just by the hook.** GitHub exposes
Agents secrets as environment variables "so they can be used by scripts and tools that Copilot
runs" — there is no hook-only channel. A prompt-injected agent can read the key, send it to any
allowlisted host, and call the gateway directly with forged telemetry. A dedicated application
limits the blast radius; it does not prevent the leak. Closing it needs short-lived per-session
tokens, or server-side validation of `github.session` and `repo`.

**`preToolUse` is best-effort against a hostile agent, not a hard stop.** GitHub fails a hook
open when it exceeds `timeoutSec`, and the agent shares our uid — so it can stall the hook, or
replace the `python3` the loader execs, and have the tool call proceed unevaluated. Bounded
reads, bounded retries and no disk dependency raise the cost of that; nothing in a hook closes
it. It holds against an agent doing ordinary work, not against one attacking the hook. Catching
that needs the gateway to notice sessions whose pre-tool checks stop arriving.

**`github.actor` is a claim, and forging it takes no attack.** It is read from the co-author
trailer GitHub stamps on the agent's *first* commit, but every later commit is one the agent
wrote — so committing with `Co-authored-by: X <victim@users.noreply.github.com>` pins the session
to whoever it names. Reading the first commit means it has to do that before anything else; it
does not make the field true. It is never sent with `preToolUse`, so it changes no policy
decision — the damage is confined to attribution. Show it as claimed, and verify it gateway-side
against `repo` and `session` before using it for anything that matters.
