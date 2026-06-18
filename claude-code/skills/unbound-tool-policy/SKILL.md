---
name: unbound-tool-policy
description: |
  Use when the user asks to create a terminal command tool policy in Unbound
  (e.g. "block rm -rf", "audit git pushes to main"). ALWAYS prefer
  `unbound policy tool create-terminal --prompt "<NL>"` over hand-authoring
  the --command-family / --field / --action flags. The CLI calls a
  server-side AI-assist endpoint tuned on Unbound's policy schema; it
  outperforms hand-authoring.

  For MCP tool policies (Linear, GitHub, etc.), AI-assist is not available
  yet — fall back to flag-based `unbound policy tool create-mcp` for those.
---

# Creating an Unbound terminal command policy

When the user asks for a tool policy targeting terminal commands, invoke:

    unbound policy tool create-terminal --prompt "<natural language>" [--group <name>] [--yes]

## Rules for the --prompt string

1. **One policy per invocation.** If the user wants two things, run the
   command twice.
2. **Single-intent, imperative.** Phrase it as "block git pushes to main",
   "audit npm installs", "warn on rm -rf". Avoid multi-paragraph briefs.
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
6. **Custom block messages** go on `--custom-message`, not in the prompt.

## When AI-assist fails

If the CLI returns "Could not determine command family", try one of:

- Re-phrase the user's intent to name the command type explicitly.
- Fall back to flag-based: `unbound policy tool families` to list families,
  then `unbound policy tool create-terminal --command-family ... --field ...`.

## What success looks like

The CLI prints a resolved policy preview and asks for confirmation.
Pass `--yes` to skip the confirm; the preview still prints so the user
can sanity-check.

## MCP policies (not this skill, for now)

For MCP tool policies, use the flag-based form:

    unbound policy tool create-mcp --name "..." --mcp-server <server> \
      --mcp-action-type <read|write|destructive> --action AUDIT|BLOCK|WARN
