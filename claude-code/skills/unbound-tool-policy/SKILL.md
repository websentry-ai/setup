---
name: unbound-tool-policy
description: |
  Use when the user asks to create a tool policy in Unbound — either a
  terminal command policy (e.g. "block rm -rf", "audit git pushes to main")
  or an MCP tool policy (e.g. "audit Linear writes", "block GitHub
  destructive ops"). ALWAYS prefer the `--prompt` form over hand-authoring
  the type-specific flags (--command-family, --field, --action for terminal;
  --mcp-server, --mcp-tool, --mcp-action-type for MCP). The CLI calls a
  server-side AI-assist endpoint tuned on Unbound's policy schema and the
  org's MCP catalog; it outperforms hand-authoring.
---

# Creating an Unbound tool policy

Two flavors. Pick based on what the user is restricting:

| If the user wants to control… | Invoke |
|---|---|
| terminal/shell commands AI tools run (`rm`, `git push`, `npm install`, etc.) | `unbound policy tool create-terminal --prompt "<NL>"` |
| MCP tools an AI agent calls (Linear, GitHub, Slack, etc.) | `unbound policy tool create-mcp --prompt "<NL>"` |

If the request is ambiguous (e.g. just "block writes to main"), ask which flavor.

## Shared rules for the --prompt string (both flavors)

1. **One policy per invocation.** If the user wants two things, run the
   command twice.
2. **Single-intent, imperative.** Phrase it as "block git pushes to main",
   "audit Linear writes". Avoid multi-paragraph briefs.
3. **Stay under 1500 characters.** The endpoint caps at 2000; the CLI
   pre-trims at 1800. Long prompts get rejected.
4. **Do NOT include** these — the endpoint cannot represent them and the
   CLI will warn about them:
   - environment scope (staging, prod, dev)
   - project / repo filters
   - time-based conditions
   - exception clauses ("except for X")
   - user-role conditions
5. **Group scoping** goes on the `--group` flag, not in the prompt.
6. **Custom block/warn messages** go on `--custom-message`, not in the prompt.
7. **Manual overrides** are allowed alongside `--prompt`: `--name`,
   `--description`, `--action AUDIT|BLOCK|WARN|REQUIRE_SLACK_APPROVAL`,
   `--custom-message`. Flag wins over the AI's choice. Use these when the
   user pins a specific value (e.g. "block it" → `--action BLOCK`).

## Terminal command policies

    unbound policy tool create-terminal --prompt "<natural language>" [--group <name>] [--yes]

Examples:

    unbound policy tool create-terminal --prompt "block rm -rf"
    unbound policy tool create-terminal --prompt "audit git pushes to main" --yes
    unbound policy tool create-terminal --prompt "block npm install" --action WARN --custom-message "Use yarn instead."

### When terminal AI-assist fails

If the CLI returns `Could not determine command family`:

- Re-phrase to name the command type explicitly ("git push" beats "pushes",
  "rm" beats "deletes").
- Fall back to flag-based: `unbound policy tool families` lists the families,
  then `unbound policy tool create-terminal --command-family <fam> --field
  <key>=<pattern> --action <action> --name "..."`.

## MCP tool policies

    unbound policy tool create-mcp --prompt "<natural language>" [--group <name>] [--yes]

### IMPORTANT: discover the catalog first

The AI-assist endpoint resolves the prompt against the org's MCP catalog
server-side, but you should know what services exist so you can write a
**specific** prompt and not have to guess.

Before invoking `create-mcp --prompt`, **run:**

    unbound policy tool mcp-servers

This lists every MCP service the org has connected (Linear, GitHub, Slack,
Notion, etc.) and the tools each exposes. Read the user's intent against
this list:

- If the user named a service that IS in the catalog → write a precise
  prompt naming the service.
- If the user named a service that is NOT in the catalog → tell them the
  service isn't connected. Don't invoke `create-mcp --prompt` with a
  service the catalog doesn't know about — the endpoint will likely return
  "no matching service".
- If the user described an action class ("writes", "destructive", "reads")
  without naming a service → ask which service they meant, OR run
  `create-mcp --prompt` per service if they want a policy for each.

### Writing MCP --prompt strings

In addition to the shared rules above:

1. **Name the service explicitly.** "audit Linear writes" beats "audit
   writes". The AI endpoint resolves named services far better than entity
   inference.
2. **Be specific about the action class.** Valid framings the AI handles
   well:
   - `audit Linear reads` — read-only tools (typically `readOnlyHint=true`)
   - `block Linear writes` — anything that creates/updates
   - `warn on Linear destructive ops` — anything with `destructiveHint=true`
     (deletes, irreversible mutations)
   - `audit Linear's get_issue and list_comments` — specific tools by name
3. **One service per invocation.** "block Linear AND GitHub writes" should
   be two `create-mcp --prompt` calls.

Examples:

    unbound policy tool create-mcp --prompt "audit all Linear writes"
    unbound policy tool create-mcp --prompt "block destructive ops on GitHub" --action BLOCK --custom-message "Require manual review."
    unbound policy tool create-mcp --prompt "warn on Slack messages from agents" --action WARN

### When MCP AI-assist fails

If the MCP endpoint returns `AI assist could not match any tools to your description`:

- The user's intent didn't map onto the catalog (either the service isn't
  connected, or no tools matched the action class).
- Re-check `unbound policy tool mcp-servers` and pick specific tool names.
- Fall back to flag-based with explicit tools:

      unbound policy tool create-mcp --name "..." \
        --mcp-server <server> \
        (--mcp-tool <tool> | --mcp-action-type <read|write|destructive>) \
        --action AUDIT|BLOCK|WARN

## What success looks like (both flavors)

The CLI prints a resolved policy preview and asks for confirmation.
Pass `--yes` to skip the confirm; the preview still prints so the user
can sanity-check. Pass `--json` for non-interactive mode that suppresses
the preview entirely.

## Error handling

Common error messages and what they mean:

| Message | Meaning | Fix |
|---|---|---|
| `Input is too long (max 1800 characters).` | Local pre-flight | Shorten the prompt. |
| `Your prompt mentions \`<keyword>\`...` (warning) | Out-of-scope token | Strip it from the prompt or accept that the endpoint will ignore it. |
| `Could not determine command family` (terminal) | AI couldn't classify | Name the command explicitly. |
| `AI assist could not match any tools...` (MCP) | Empty `mcp_tools` after backend validation | Check `mcp-servers`, name tools explicitly, or fall back to flag-based. |
| `Authentication failed / not authorized. Tool policies require admin.` | Non-admin API key | Ask the user's admin to run it, or provide an admin key. |
| `Request validation failed: ...` | Server rejected the body | Surface the body to the user; usually a missing required field. |
| `Server error.` / `Network error reaching ...` | Backend or network | Try again; if persistent, suggest flag-based. |
