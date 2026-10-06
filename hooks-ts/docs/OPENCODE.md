# Unbound hooks for opencode — scope, gaps and bypasses

Author: Sumit Badsara

This page states what the Unbound opencode plugin enforces, what it only records, what it does not
see at all, and which switches turn it off. It is written so install copy and the Connect tile can
quote it without overclaiming. Everything below is about the **v1 plugin line (opencode 1.18.x)**
unless a row says otherwise.

## What it is

- One bundle, `opencode/index.js`, built from `packages/opencode`. Its single default export is
  `{ id: "unbound", server, setup }`: `server` is the v1 plugin factory, `setup` is the v2 entry.
- Installed as one file:
  `${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-~/.config}/opencode}/plugins/unbound.js`.
  opencode loads plugins at startup, so a **restart is required** after install or update.
- The installer never writes an opencode config file (`opencode.json` and friends stay untouched).
- `server()` does no I/O. The API key, gateway URL and policy cache are resolved lazily on the
  first hook call. A fault while the plugin starts gives an allow-everything hook set that reports
  `init_degraded`; it never loads silently empty. A fault while resolving the key, gateway or
  checker on a hook call allows the call, shows its own notice ("could not start"), reports
  `init_degraded` (detail `resolve_fault`) once, and is retried after a few seconds.
- Without an Unbound API key the plugin sends nothing and shows one notice per project directory.
  It looks for a key again about every 30 s, so a key added later takes effect without a restart.

## Enforced on opencode 1.18.x (v1)

| What | How it behaves |
|---|---|
| Model-issued shell and file tools (`tool.execute.before`) | `bash` and the file tools `read`, `write`, `edit`, `grep`, `glob`, `lsp` and `apply_patch` are evaluated by the Unbound policy engine before they run. |
| MCP tools | Sent for evaluation with an explicit server and tool, attributed by the configured (or live, `client.mcp.status()`) MCP server names, or by the call's own server argument for resource tools; never by splitting the tool id. When more than one configured server could have produced the tool id (sanitised names can collide), the call is checked once per candidate server and the strictest verdict wins; this is reported as `mcp_attribution_ambiguous`. A non-built-in tool that matches no known server is still sent, with its raw id and no MCP attribution, and reported as `mcp_attribution_miss` (also when no MCP server is configured). |
| Custom (plugin-defined) tools | Sent with their raw tool id and no MCP attribution. The server has no evaluation path for them today: it logs the call (an attribution miss) and allows it. So a custom tool runs unchecked, but it is visible server-side. |
| `webfetch`, `websearch`, `skill` | **Not sent.** The server has no evaluation path for these tools under `opencode`, so a URL-fetch or search policy cannot apply to them. They run unchecked. The same holds for `todowrite`, `question`, `plan_exit`, `invalid` and the outer Code Mode `execute` call (the MCP calls made inside it are checked one by one). |
| Tools inside subagents | A subagent's own tool calls are checked like the root session's. |
| `apply_patch` | Checked once per file named in the patch; the strictest verdict wins. All the per-file checks of one call share a single deadline (see below). A patch that names more than 1024 files is blocked without a check ("patch too large to verify"). |
| Deny | The model receives the deny text verbatim: `Blocked by Unbound policy: <reason>` (spike V1-1). The turn continues and the model can explain or choose another approach. A toast shows the same text. |
| Approval required | Blocked with its own approval sentence: v1 has no native approval prompt, so the action does not run and the model is told to ask an Unbound admin. |
| Root-session user prompts (`chat.message`) | The non-synthetic text the user typed is checked before it is persisted or sent to the model (spike V1-5). A slash command that runs as a subtask arrives as the command template with the user's arguments filled in, and that text is checked the same way. On a block the reason is toasted first. Host-generated (`synthetic`) text and prompts in subagent sessions are not checked. **Caveat:** `opencode run` and synchronous API callers see only a generic `Unexpected server error`; the reason is in the toast and the server log. |
| User `!cmd` (`shell.env`) | Checked through the same path as a model `bash` call (spike V1-7). The command is recovered from the bash part opencode persists just before it spawns the shell. A model bash call that already passed `tool.execute.before` is never checked twice. **Caveats:** the HTTP caller gets a generic 500 `UnknownError`; the session transcript records the blocked command as `completed` with empty output (it did not run); TUI rendering of a blocked `!cmd` is not yet human-verified. A `shell.env` call that finds no bash part to check is allowed and reported as `user_shell_unchecked`. |
| `task` (subagent launch) | Audited, never denied: a deny there would strand the subtask. Each tool call inside the subagent is enforced on its own. |
| Unreachable or failing Unbound API | **Fail-open**: the call is allowed and the bypass is reported. Each tool call's check is bounded by a 20 s deadline. That deadline is the plugin's own: opencode 1.18.x puts no time limit on a plugin hook (spike V1-3). An `apply_patch` (one check per file) or an ambiguous MCP call (one check per candidate server) runs all its checks under one shared deadline; on expiry no further check starts, a deny already received still blocks, and otherwise the org's failure action decides. After repeated failures a per-gateway breaker opens and later calls skip the request for a while (one notice). |
| Fail-closed orgs | When the org's last successful response asked for `policy_check_failure_action: block`, a failed check blocks with `Unbound policy engine unavailable — please retry`. |
| Revoked API key | One notice; after that the plugin stops every request (checks, audits, turn logs, signals) for that key. |

## Recorded

- **Tool results, hash-only.** Every model-issued tool result (successful, failed or blocked) is
  recorded once per call as a sha256 plus byte count. Tool output never leaves the device in clear;
  it is never logged locally either. The result of a user `!cmd` is not recorded (the check of the
  command is).
- **Turn log.** When a root session goes idle, one turn log is posted (model `auto`) with the prompt,
  the tool calls of the turn including those made inside its subagents, and the assistant's text.
  The turn log carries the user prompt and the assistant's text in clear (capped). Subagent idles
  post nothing; a deleted session's pending state is dropped, not posted.
- **Heartbeat.** On a new root session, at most once per project directory per cache TTL, carrying
  the opencode version (`metadata.opencode_version`). Requests use `client_entrypoint`
  `opencode/<version>` once the version is known.
- **Account identity.** Read from opencode's `auth.json` for the provider the prompt used, and sent
  as the auth mode only (plus the device serial). No credential value is ever sent.
- **Policy cache.** `<opencode config dir>/.unbound/policy_cache.json`, mode 0600, bound to the
  gateway URL and a key fingerprint. A list read from disk never skips a check until one
  server-confirmed pull has happened in the current process.

## Not hooked

| Surface | Status |
|---|---|
| User `!cmd` | **Enforced** (see above), with the documented caveats. |
| `` !`cmd` `` inside custom command templates | Not hooked. Template shell expansion does not go through a hook the plugin can block. |
| The integrated terminal (PTY) | Not hooked. Opening a PTY fires `shell.env` with only a working directory (no session, no command), which the plugin ignores; the commands typed into it are invisible to plugins. |
| Processes opencode starts from config | Not hooked: MCP server processes, LSP servers and formatters are spawned from configuration, not as tool calls. The MCP *tool calls* themselves are enforced. |
| Remote `opencode attach` | Plugins run where the opencode server runs. Install the plugin on the server host; a client that attaches remotely is covered only if the server has it. |
| opencode v2 (desktop / CLI 2.x) | The `setup` entry is present but **inactive** in this line: nothing is enforced on a v2 host. When it detects a v2 host it reports `api_family_inactive`. On a 1.18.x host, which also calls `setup`, it stays silent because the v1 `server` entry is the active one. |
| Tool-output content inspection (DLP) | Out of scope, as on pi: output is recorded hash-only. |

## Bypasses

| Switch | Effect |
|---|---|
| `opencode --pure` / `OPENCODE_PURE=1` | Plugins are not loaded at all: the module is not even evaluated, and nothing is logged (spike V1-10). Nothing is enforced or recorded. |
| `XDG_CONFIG_HOME`, `HOME` or `OPENCODE_CONFIG_DIR` pointing elsewhere | opencode looks for global plugins in a different directory, so an installed `plugins/unbound.js` is not loaded (source-read; not live-verified). |
| `OPENCODE_PERMISSION` | Changes opencode's own permission rules (for example, turning its approval prompts off). Not a bypass of Unbound checks, which run regardless, but it removes opencode's own second line of defence. |
| Another plugin changing tool arguments after the Unbound check | Not prevented. Detected after execution and reported as `args_changed_after_check`. |
| Project-level plugins from a cloned repository (`.opencode/plugins/`) | opencode loads them automatically, in the same process as the Unbound plugin. They can change tool arguments after the check, or otherwise interfere with it. A value planted in the plugin's double-load slot does not switch enforcement off: the plugin keeps enforcing and reports `sentinel_tampered`. Only a forged copy of the exact installed build's marker (which means reading the installed file) makes it stand down as a duplicate. |
| API key changes | A key that changes or is removed while opencode runs takes effect only after an opencode restart. (A key added where none was found is picked up within about 30 s.) |
| A hook that fails or times out | Fail-open by design (except fail-closed orgs). This is the general limitation of hook-based enforcement, not specific to opencode. |

## Signals

Every signal is posted to `/v1/hooks/errors` with `hook_source: "opencode-hook"`, rate-limited per
category, and never sent after the key is latched as revoked. Signals are observations; none of
them blocks anything.

| Category | Triggered when |
|---|---|
| `bypassed_due_to_failure` | A check failed (timeout, connection error, non-2xx, unparseable body) and the call was allowed. |
| `blocked_due_to_failure` | A check failed for a fail-closed org and the call was blocked. |
| `turn_log_failed` | The turn log for an idle root session could not be posted. |
| `duplicate_load` | A second copy of the same plugin build loaded into the same process (for example one in `plugin/` and one in `plugins/`). The second copy does nothing. |
| `sentinel_tampered` | The double-load slot held something other than a copy of this build (a planted value, an accessor, another build). The plugin keeps enforcing. |
| `init_degraded` | The plugin factory faulted and the allow-everything hook set is serving (detail `factory_fault`), or resolving the key, gateway or checker faulted and is being retried (detail `resolve_fault`). |
| `mcp_attribution_miss` | A non-built-in tool matched no known MCP server name; it was sent without MCP attribution. |
| `mcp_attribution_ambiguous` | More than one configured MCP server could have produced the tool id; the call was checked once per candidate. |
| `patch_targets_capped` | An `apply_patch` named more files than the per-call cap (1024); the call was blocked. |
| `args_changed_after_check` | A tool's arguments at execution differed from the ones checked. |
| `user_shell_unchecked` | `shell.env` fired for a call with no bash part to check (detail `no_part`); the command was allowed. |
| `api_family_inactive` | The v2 entry was loaded on a v2 host, where this line enforces nothing. |

## Spike outcomes

Results of the live spikes in the Phase 13 planning record (`13-SPIKES.md`):

| Spike | Result |
|---|---|
| V1-1 deny text | PROVEN on the CLI: the model gets the deny text verbatim. Desktop (Electron) human-verification pending. |
| V1-2 dual-entry export | PROVEN: `{id, server, setup}` loads on v1; opencode 1.18 also calls `setup` with a v1 context, so `setup` is inert there. |
| V1-3 hook hang | PROVEN: without a deadline a headless `run` hangs forever; the plugin's 20 s deadline is mandatory. TUI Esc behaviour pending human verification. |
| V1-4 ESM and rejected `event` | PROVEN on Bun: the ESM bundle loads; a rejected `event` does not kill the host but prints to stderr, so the handler never rejects. Plain Node 22 needs an ESM `package.json` next to the plugin. |
| V1-5 prompt block | PROVEN: blocking in `chat.message` stops the prompt before persistence and before any model call; callers see a generic error, hence the toast. |
| V1-6 deny shape for SDK callers | PROVEN: the tool part carries `status: "error"` and the verbatim reason. |
| V1-7 user `!cmd` | PROVEN on the shell route: the bash part arrives before `shell.env` (6/6), a block prevents the spawn (6/6), and model bash is not checked twice. TUI rendering pending human verification. |
| V1-9 multiple directories | PROVEN on `serve`: one module, one hook set per directory. |
| V1-10 `--pure` | PROVEN: plugins are skipped entirely. |
| V1-11 toast | PROVEN callable; visibility in the TUI pending human verification. |
