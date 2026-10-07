# Unbound hooks for opencode — scope, gaps and bypasses

Author: Sumit Badsara

This page states what the Unbound opencode plugin enforces, what it only records, what it does not
see at all, and which switches turn it off. It is written so install copy and the Connect tile can
quote it without overclaiming. Everything below is about the **v1 plugin line (opencode 1.18.x)**
unless a row says otherwise; the **v2 line (opencode desktop / CLI 2.0.x)** has its own section,
`## opencode v2`.

## What it is

- One bundle, `opencode/index.js`, built from `packages/opencode`. Its single default export is
  `{ id: "unbound", server, setup }`: `server` is the v1 plugin factory, `setup` is the v2 entry.
- Installed as one file:
  `${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-~/.config}/opencode}/plugins/unbound.js`.
  opencode loads plugins at startup, so a **restart is required** after install or update.
- The per-user installer never writes an opencode config file (`opencode.json` and friends stay
  untouched). The MDM installer additionally writes one plugin entry into opencode's
  system-managed `opencode.json` on 1.x. That entry references a root-owned copy of the plugin, so
  every account on the machine loads it.
- **Managed and per-user copy side by side (1.x).** Both copies load in every opencode process, and
  the seat is enforced either way:
  - When they are the same build, one copy enforces and the other stands down. The second copy
    reports `duplicate_load` once per process (an informational signal, not an alert).
  - When a later per-user install puts a newer build next to an older managed copy, both copies
    enforce, so each call is checked twice. `duplicate_load` with detail `other_build` is reported
    instead of `sentinel_tampered`. This lasts until the next MDM push brings the managed copy to
    the same build.
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
| MCP tools | Sent for evaluation with an explicit server and tool, attributed by the configured (or live, `client.mcp.status()`) MCP server names, or by the call's own server argument for resource tools; never by splitting the tool id. When more than one configured server could have produced the tool id (sanitised names can collide), the call is checked once per candidate server and the strictest verdict wins; this is reported as `mcp_attribution_ambiguous`. A non-built-in tool that matches no known server is still sent, with its raw id and no MCP attribution, and reported as `mcp_attribution_miss` (also when no MCP server is configured). **Arguments** go through the same allowlist and caps as a native tool, not whole: server- and tool-level MCP policies apply, but argument-level MCP policies and MCP input DLP do not see the arguments. (pi sends brokered MCP arguments whole, up to 512 KiB; extending that egress to opencode is a separate product decision.) |
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

## opencode v2 (desktop / CLI 2.0.x)

The same bundle enforces on opencode 2.0.x through its `setup` entry. Each row below follows the
verdict of the Phase 14 spikes (planning record `14-SPIKES.md`, tested on `@opencode/cli` 2.0.22;
the loader smoke runs on the current 2.0.x). Every decision is made by the same policy path as v1;
only the way it is applied differs.

| Capability | Status on v2 | Evidence |
|---|---|---|
| Bundle loading (HV2-01) | Loads: one bundle for both lines | HV2-01 GO. opencode 2.x calls `setup` once per project directory and never calls `server`; the plugin keeps one runtime per process. With several directories open in one process (the desktop app), each call is checked once. On 2.0.24 a tool, permission, prompt or shell hook fires only in the registration of the call's own directory. The event stream reaches every registration, so each event is handled by its own directory's registration, and by exactly one when its directory cannot be told. On 1.18.x, which also calls `setup`, it stays inert: it activates only on a context that has all of `tool`, `permission`, `session` and `event`. The nightly `loader-v2` job is required. |
| Tool calls (HV2-02) | Enforced (through opencode's permission hook) | HV2-02 GO. The check runs in `tool.execute.before`. Its verdict is applied in `permission.evaluate`: a deny sets the permission effect to deny with the verdict text, and the model receives `Blocked by Unbound policy: <reason>` verbatim (`permission.rejected`); the turn continues. Tool names follow v2: `shell` is checked as `bash`, file tools read `path`, `write` is checked as `write`. `subagent` (v1 `task`) is audited, never denied. Tool coverage is otherwise the same as v1: `webfetch`, `websearch`, `skill` and `question` are not sent. A host or user rule that already denies is never loosened. A built-in call that the permission step cannot be matched to is blocked by a raise from `tool.execute.before` instead (the model gets the same text). This happens when the call has no session or call id, or once the host asserted a permission without its call id (reported as `init_degraded`, detail `evaluate_no_source`). |
| Approval required (HV2-03) | Native approval prompt | HV2-03 NATIVE. An approval verdict sets the permission effect to `ask` with `Unbound policy requires approval: <reason>. Approve it only if you expect it.`, so opencode shows its own approval. Reject prevents execution; allow-once runs it (proven through the API). |
| MCP tools (HV2-04) | Enforced (raised from `tool.execute.before`) | HV2-04 GO. MCP ids reach the hooks as `<server>_<tool>`. They are attributed against the host's live server list (`ctx.mcp.list()`) and checked like v1. A blocked call is raised from `tool.execute.before`, because a permission deny on an MCP id replaces the reason with "Unable to execute"; the model gets the verdict text verbatim. In Code Mode (the default), each inner MCP call is checked on its own. An approval verdict on an MCP tool blocks with the v1 approval sentence: a native approval for MCP was not exercised. |
| User prompts (HV2-05) | Blocked (the prompt is replaced with a block notice) | HV2-05 BLOCK. A root prompt that would be blocked is replaced before it is persisted or sent: its text becomes the verdict plus a notice telling the model to tell the user the message was blocked, and its attached files, agents and skills are cleared. The original text never reaches the model. Subagent prompts are not checked (the parent comes from `ctx.session.get`, else from the host's subagent preamble). A prompt is replaced only for a session known to be a root, from `ctx.session.get` or from its `session.created`. If neither answers in time (1 s), the prompt is checked but not replaced, and `v2_not_enforcing` (detail `parent_unknown`) is reported. **Caveat:** the notice, not the typed text, is what the transcript shows. |
| User `!cmd` shell (V2-10) | Checked, raised on a block (with caveats) | V2-10 PROVEN. A user shell (`POST /api/session/:id/shell`) fires `shell.create.before` before anything spawns. The command is checked as `bash` through the same path as v1's `!cmd`; a deny or an approval verdict prevents the spawn. The model's own `shell` calls fire the same hook (after their check, before the permission step); each is recognised and not checked twice. The recognition mark is set only once the model call's decision is in, right before the spawn hook of that call follows. It is bound to the command and the working directory, lives 5 s, is used once, and is dropped when the session is interrupted. On 2.0.x the user routes spawn with `timeout: 0` and the model tool with its own timeout, so a user `!cmd` never uses a mark. A mark from a denied model call can only be used by the tool's own spawn. A user command sent while the model's identical command is still being checked, or after it was denied or interrupted, is therefore always checked. The same hook also fires for opencode's non-session shell API (`POST /api/shell`), which the plugin cannot tell apart from a `!cmd` (same input, no session; 2.0.24). Those commands are checked too, and a deny or approval verdict blocks them. A fail-closed "engine unavailable" verdict never blocks a spawn here, because it carries no session id; it is reported as `user_shell_unchecked` (detail `unavailable_not_applied`). The integrated terminal (PTY) and opencode's own git reads do not go through this hook on 2.0.24. **Caveats:** the caller sees an empty HTTP 500 and nothing is persisted, and no notice is shown (no v2 toast channel is proven). The hook carries no session, so the check is sent with an empty conversation id and is not part of any turn log. In some cases a model command is checked a second time as a user command (never skipped):<br>- another plugin rewrites it;<br>- another plugin's before hook delays its spawn past 5 s;<br>- the model sets a zero timeout. |
| Audit, turn log, heartbeat (HV2-06) | Recorded from v2 events | HV2-06 GO. Heartbeat on a root `session.created`, carrying the host version (`data.version`, else `ctx.app.version`). Turn log on `session.execution.succeeded` / `interrupted` / `failed` (`session.idle` never fires on 2.0.x; a turn that fails at the provider is posted too), with the prompt, the turn's tool calls (subagents rolled in) and the assistant text from `session.text.ended`. Tool results are hash-only, from `tool.execute.after` and `session.tool.failed`, once per call; In Code Mode the inner calls share the outer call id. Each inner call and its result get the same numbered id (`<id>`, `<id>#1`, …), so they pair in the turn log. While several inner calls run in parallel, the argument comparison after execution is skipped, because their results can finish out of order. Model from `session.step.started` / `session.model.request`. Tokens and cost are not sent (as on v1). |
| Account identity (HV2-07) | Device serial only (credential store not read) | HV2-07 PROVIDER-LEVEL. The session's provider comes from `session.model.request`, but it stays on the device. Neither the provider id nor a custom provider name is ever sent. `auth_mode` uses only the shared vocabulary (`subscription` / `api_key`), and v2 cannot tell which one applies, so `auth_mode` is omitted on v2. The identity carries the device serial only. opencode 2.x keeps credentials in its own database; the plugin never opens it, and no account email or plan is sent. |

**v2 status signal.** Once per process the plugin reports `v2_status` with every capability, for
example `tools:enforce/ask:native/mcp:enforce/prompt:block/recording:full/identity:provider/shell:enforce`.
If no API key is found at start, the report goes out with the first call after a key is found. A seat whose tool calls ran audit-only would also report `v2_not_enforcing`. The shipped build
enforces every capability above.

**Pending human verification (desktop 2.x UI):** native approval card rendering; deny rendering for a
built-in tool and an MCP tool; what the user sees for a replaced prompt; a blocked user `!cmd`; Esc /
stop on a hung check; toast visibility; native approval on an MCP tool; the `skill` tool with a real
skill.

## Recorded

- **Tool results, hash-only.** Every model-issued tool result (successful, failed or blocked) is
  recorded once per call as a sha256 plus byte count. Tool output never leaves the device in clear;
  it is never logged locally either. The result of a user `!cmd` is not recorded (the check of the
  command is).
- **Turn log.** When a root session goes idle, one turn log is posted (model `auto`) with the prompt,
  the tool calls of the turn including those made inside its subagents, and the assistant's text.
  The turn log carries the user prompt and the assistant's text in clear (capped). Subagent idles
  post nothing; a deleted session's pending state is dropped, not posted.
- **Pretool requests carry no prompt.** `messages[0].content` is empty on tool-call checks, so a
  gateway block/warn row shows the command without the prompt that led to it; the prompt is in the
  turn log. (pi sends the turn prompt on tool calls; extending that to opencode is a separate change.)
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
| The integrated terminal (PTY) | Not hooked. Opening a PTY fires `shell.env` with only a working directory (no session, no command), which the plugin ignores; the commands typed into it are invisible to plugins. On v2 (2.0.24) creating a PTY fires no plugin hook at all. |
| Processes opencode starts from config | Not hooked: MCP server processes, LSP servers and formatters are spawned from configuration, not as tool calls. The MCP *tool calls* themselves are enforced. |
| Remote `opencode attach` | Plugins run where the opencode server runs. Install the plugin on the server host; a client that attaches remotely is covered only if the server has it. |
| opencode v2 (desktop / CLI 2.x) | **Enforced** through the `setup` entry; see `## opencode v2`. On a 1.18.x host, which also calls `setup`, it stays inert because the v1 `server` entry is the active one. |
| Tool-output content inspection (DLP) | Out of scope, as on pi: output is recorded hash-only. |

## Bypasses

| Switch | Effect |
|---|---|
| `opencode --pure` / `OPENCODE_PURE=1` | Plugins are not loaded at all: the module is not even evaluated, and nothing is logged (spike V1-10). Nothing is enforced or recorded. |
| `XDG_CONFIG_HOME`, `HOME` or `OPENCODE_CONFIG_DIR` pointing elsewhere | opencode looks for global plugins in a different directory, so an installed `plugins/unbound.js` is not loaded (v1: source-read; not live-verified). |
| `OPENCODE_CONFIG_DIR` on v2 | On opencode 2.x it **replaces** the XDG config dir rather than adding to it (spike V2-7): while it is set, plugins and `opencode.json` in `~/.config/opencode` are ignored. The installer must write into it when it is set. |
| Other plugin directories on v2 | `~/.claude/plugins` and `~/.agents/plugins` are not plugin directories on opencode 2.x (spike V2-6): a copy placed there is not loaded. |
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
| `duplicate_load` | Informational. A second copy of the same plugin build loaded into the same process (for example one in `plugin/` and one in `plugins/`); the second copy does nothing. On v2 (tool `setup`, detail `second_copy`): `setup` ran again for a directory that already has the plugin's handlers. Detail `other_build` (tool `server` or `setup`): another genuine build of the plugin already holds the slot, for example after an in-place upgrade or with a managed copy beside a newer user copy. This copy keeps enforcing too, so each call is checked by both until one of them goes (an opencode restart, or the next managed install). |
| `sentinel_tampered` | The double-load slot held something other than a genuine copy of this plugin: a planted value, an accessor, or a holder that only imitates another build. The plugin keeps enforcing. The v2 entry has its own slot with the same rule. |
| `init_degraded` | The plugin factory faulted and the allow-everything hook set is serving (detail `factory_fault`), or resolving the key, gateway or checker faulted and is being retried (detail `resolve_fault`). On v2, registering the handlers on the host faulted (detail `registration_fault`); what was registered stays, the rest is not registered. On v2 (tool `permission.evaluate`, detail `evaluate_no_source`): the host asserted a permission without the call id, so built-in blocks are raised from `tool.execute.before` from then on. |
| `mcp_attribution_miss` | A non-built-in tool matched no known MCP server name; it was sent without MCP attribution. |
| `mcp_attribution_ambiguous` | More than one configured MCP server could have produced the tool id; the call was checked once per candidate. |
| `patch_targets_capped` | An `apply_patch` named more files than the per-call cap (1024); the call was blocked. |
| `args_changed_after_check` | A tool's arguments at execution differed from the ones checked. |
| `user_shell_unchecked` | `shell.env` fired for a call with no bash part to check (detail `no_part`); the command was allowed. On v2 (detail `unavailable_not_applied`): a spawn with no session id was checked, the engine was unavailable for a fail-closed org, and the spawn was not blocked. |
| `v2_status` | Once per process on an opencode 2.x host (tool `setup`): the per-capability status, `tools:<enforce\|audit>/ask:<native\|deny\|audit>/mcp:<enforce\|audit\|none>/prompt:<block\|warn>/recording:<full\|partial>/identity:<provider\|none>/shell:<enforce\|audit\|none>`. |
| `v2_not_enforcing` | On v2, a capability built audit-only found a call it would have blocked, or tool calls are audit-only for the whole seat. Not sent by the shipped build unless a capability is switched to audit, with two exceptions, both on tool `prompt`. Detail `parent_unknown`: a prompt would have been blocked, but its session could not be confirmed as a root, so it was left unchanged. Detail `prompt_mutate_failed`: the host passed a prompt that could not be replaced, so it went through. |
| `v2_prompt_warn_only` | On v2 with the prompt capability warn-only, a prompt would have been blocked (once per session). Not sent by the shipped build (prompts are blocked). |
| `api_family_inactive` | No longer sent by this bundle (replaced by `v2_status`). |

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

Results of the v2 spikes in the Phase 14 planning record (`14-SPIKES.md`, `@opencode/cli` 2.0.22):

| Spike | Result |
|---|---|
| V2-1 bundle on both lines | PROVEN: the committed dual-entry bundle loads on 2.x (`setup` called) and on 1.18.x. |
| V2-2 deny lever | PROVEN: a permission deny with a message reaches the model verbatim for every built-in tool that asserts a permission; a raise from `tool.execute.before` also works. Two live turns confirmed the block. |
| V2-3 MCP | PROVEN: ids `<server>_<tool>` reach the hooks (Code Mode and direct); a raise blocks with the reason, a permission deny drops it. |
| V2-4 prompt block | PROVEN: replacing the prompt text keeps the original from the model; a raise also blocks, with an empty HTTP 500. |
| V2-5 events | PROVEN: session, execution, text, step, tool and permission events carry what recording needs; `session.idle` is never emitted. |
| V2-6 other plugin dirs | DISPROVEN: `~/.claude/plugins` and `~/.agents/plugins` are not loaded. |
| V2-7 `OPENCODE_CONFIG_DIR` | PROVEN: it replaces the XDG config dir. |
| V2-8 credential storage | PROVEN (shape only): credentials live in opencode's database; nothing needs them. |
| V2-9 hook hang | PROVEN: no host-side hook timeout; the plugin's deadline is mandatory, and interrupting the session recovers it. |
| V2-10 user shell | PROVEN: `shell.create.before` fires before the spawn; a raise there prevents it (empty HTTP 500, nothing persisted). |
| V2-11 tool names | PROVEN: `shell`, `subagent`, `path`; no `bash`, `task` or `apply_patch`. |
| V2-12 directories | PROVEN: `setup` runs once per directory; the module is re-evaluated per directory with `globalThis` shared. |
