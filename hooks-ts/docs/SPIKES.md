# Spikes — HOOK-07, and the gaps we ship on purpose

HOOK-07 asks two questions that a design document cannot answer: does policy still apply to tool
calls made *inside* a pi subagent, and does it apply to tools that are not pi's own? Both were
re-run against the installed pi `0.87.1` on 2026-09-27 (UTC) with the Phase 9 build
(`dist/pi/index.js`, 52 771 bytes) installed at `~/.pi/agent/extensions/unbound/index.js` and the
repo's own scripted mock on `http://127.0.0.1:8799`. Headless runs used
`--model openrouter/openai/gpt-4.1-nano` (the default Anthropic provider is out of usage).

Every request body quoted below was captured by a body-logging wrapper around
`packages/core/test/helpers/mockApi.ts` — the same mock `npm run mock-api` runs, with the parsed
body written to an NDJSON file, because the standard runner logs only method and path.

The API key in every run below is the literal string `test` against a loopback mock. No staging
key, host or customer identifier appears in this file.

---

## Spike A — does a custom (extension-registered) tool reach our handler?

**Question.** pi lets an extension register its own tools (`pi.registerTool`). Do those calls go
through Unbound policy, or do they bypass it?

**Command.** A throwaway second extension was installed at `~/.pi/agent/extensions/zz-spike/index.ts`
(loaded *after* `unbound` by alphabetical directory order), registering one inert echo tool:

```ts
export default (pi) => {
  pi.registerTool({
    name: "spike_echo", label: "Spike Echo", description: "Echo text back for a spike test.",
    parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
    async execute(id, params) { return { content: [{ type: "text", text: String(params.text) }], details: undefined, isError: false }; },
  });
};
```

```bash
# mock in --mode allow (see the note below on why not --mode deny)
UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test \
  pi -p --mode json --model openrouter/openai/gpt-4.1-nano \
  "Call the spike_echo tool with text=hello, then read the file package.json." < /dev/null
```

**Output — the tool ran:**

```
tool_execution_start spike_echo "call_LMurJdzVW4GaALgvXGelxWjl"
tool_execution_end   spike_echo "call_LMurJdzVW4GaALgvXGelxWjl" [{"type":"text","text":"hello"}]
```

**Output — every request the mock received during that run** (`read` is the same turn's native
file tool, included as the control):

```
#1 /v1/hooks/pretool event=session_start tool=""     pull=true
#2 /v1/hooks/pi      (turn log)
#3 /v1/hooks/pretool event=user_prompt  tool=""
#4 /v1/hooks/pretool event=tool_use     tool="read"  pull=true  metadata.file_path="package.json"
#5 /v1/hooks/pi      (turn log)
```

**There is no request for `spike_echo`.** It is also absent from the turn log's `tool_use[]`,
which carries only the `read` call.

**Conclusion — custom tools are covered, and correctly not round-tripped.** The coverage claim is
structural, not statistical: `beforeToolCall`/`afterToolCall` are installed **once on the agent**,
not per tool wrapper (`agent-session.js:239-243`, "Tool call and tool result interception now
happens here instead of in wrappers"), and `:245-263` emits `tool_call` for `toolCall.name`
whatever its origin, after `_refreshToolRegistry` (`:2491-2520`) has merged extension-registered
tools into the same registry as the built-ins. So `spike_echo` *did* reach our `tool_call` handler.
What it did not do is produce an HTTP request, because a custom tool carries neither a shell
command nor a `metadata.file_path` and the "nothing evaluable ⇒ no request" guard (RESEARCH §C4,
shipped in 09-02) skips it. That is the intended outcome, not a gap: the server's own Path-2 entry
gate would have answered `allow` with `_entry_gate: no_evaluable_input` anyway, so the request
would have cost a round trip to learn nothing. A tool nobody wrote a policy for is not blocked, and
synthesising a fake command out of `JSON.stringify(input)` so that *something* could match was
already declined on PR #348 (finding 5).

**What would change this.** If the API ever grows a policy surface keyed on custom tool names
(today the name would miss `ALLOWED_TOOL_NAMES` and land on the final `no_policy` allow,
`preToolUseHandler.ts:1008-1012`), the guard needs an exception for names carrying
`metadata.mcp_server`/`mcp_tool`. **Re-check trigger:** a new tool-name-keyed policy type in the API.

**Why `--mode allow` and not `--mode deny`.** See "A note on mock modes" below — in `deny` mode the
prompt itself is denied and the model is never invoked, so no tool call of any kind ever happens.

---

## Spike B — does a nested `pi` process enforce independently?

**Question.** pi 0.87.1 has no subagent feature (Spike C), but a tool call or a `!cmd` can launch a
second `pi`. Is that child invisible to policy?

**Command.**

```bash
UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test \
  pi -p --mode json --model openrouter/openai/gpt-4.1-nano \
  'Run this exact bash command and show its output: pi -p --model openrouter/openai/gpt-4.1-nano "run: echo nested"' < /dev/null
```

**Output — every request, annotated with its `conversation_id`:**

```
#6  /v1/hooks/pretool event=session_start tool=""     conv=01a0e268-e231-7755-8da6-8312af2ef3db   <- OUTER
#7  /v1/hooks/pi      (turn log)                      conv=01a0e268-e231-...
#8  /v1/hooks/pretool event=user_prompt  tool=""      conv=01a0e268-e231-...
#9  /v1/hooks/pretool event=tool_use     tool="bash"  conv=01a0e268-e231-...
     command = "pi -p --model openrouter/openai/gpt-4.1-nano \"run: echo nested\"}"
#10 /v1/hooks/pretool event=session_start tool=""     conv=01a0e268-ec19-7479-8eb1-c69a9e3eb5c1   <- INNER
#11 /v1/hooks/pi      (turn log)                      conv=01a0e268-ec19-...
#12 /v1/hooks/pretool event=user_prompt  tool=""      conv=01a0e268-ec19-...
#13 /v1/hooks/pi      (turn log)                      conv=01a0e268-ec19-...
#14 /v1/hooks/pi      (turn log)                      conv=01a0e268-e231-...
```

**Conclusion — PASS. A nested `pi` is a fully independent enforcement point.** Two distinct
`conversation_id` values appear, and the inner process ran the whole chain of its own accord: its
own `session_start` heartbeat (#10), its own `user_prompt` check (#12) and its own turn logs — while
the outer process separately submitted the nested launch itself for evaluation as a `bash` command
(#9). A nested pi loads the global extension through the ordinary discovery chain, and gets its own
session id, its own cache read and its own heartbeat.

**Honest limits of this run.** The strictest form of the PASS criterion — two `tool_use` requests,
one from each process — was **not** observed, because the inner `gpt-4.1-nano` answered
`run: echo nested}` in prose ("The command executed successfully with the output: \"nested}\"")
instead of calling `bash`. Note also the stray `}` the outer model appended to the command it
emitted: a nano-model artifact, not an extension behaviour. The inner process's independent
enforcement is nonetheless proven by #10/#12/#13, which only our extension inside that child could
have produced. **Re-check trigger:** none needed; re-run with a stronger model if a future change
makes the inner tool call itself load-bearing.

**Adjacent bypass, already known.** An SDK embedder (`createAgentSession()`) loads extensions
through `DefaultResourceLoader` and gets ours by default, but can set `noExtensions`
(`resource-loader.js:121,170,316-318`) — the same bypass class as `--no-extensions` and
`PI_CODING_AGENT_DIR`. Listed in the gap table below.

---

## Spike C — is there any subagent concept in pi 0.87.1?

**Question.** HOOK-07's first half assumes pi has subagents. Does it?

**Commands and output:**

```bash
$ PI=~/.pi/agent/install/releases/0.87.1/node_modules/@earendil-works/pi-coding-agent
$ grep -ril subagent "$PI/dist" | grep -v '\.map$'
(no output, exit 1)

$ node -e 'console.log(require("fs").readFileSync(process.env.HOME+"/.pi/agent/install/releases/0.87.1/node_modules/@earendil-works/pi-coding-agent/dist/core/tools/index.js","utf8").match(/allToolNames[\s\S]{0,200}/)[0])'
allToolNames = new Set([
    "read",
    "bash",
    "powershell",
    "edit",
    "write",
    "grep",
    "find",
    "ls",
]);
export function createToolDefinition(toolName, cwd, options) {
    switch (toolNam
```

**Conclusion — the feature does not exist.** The string `subagent` appears nowhere in the shipped
`dist/`, and the complete built-in tool set contains no Task/Agent/dispatch tool through which one
could be spawned. "Tool calls inside pi subagents" is therefore not a parity gap in 0.87.1 — there
is nothing to cover. The closest real thing is a nested `pi` process, which Spike B shows enforces
independently.

**Re-check trigger: re-verify on the next pi minor.** This is the one claim in this file that a
routine `pi update` could silently invalidate. Re-run both commands above; if a dispatch tool
appears, HOOK-07 reopens and the new tool's child calls need their own `conversation_id` audit.

---

## A note on mock modes (discovered while running these spikes)

`--mode deny` denies **every** request uniformly, and `user_prompt` is exempt from the mock's
Path-2 entry gate (`mockApi.ts:129-133`), so the prompt check (HOOK-05) denies the prompt before
the model is ever invoked:

```
$ ... pi -p --mode json ... "Call the spike_echo tool with text=hello. Do not use bash."
Blocked by Unbound policy: Reading secrets is blocked.     # on stderr, exit 0
# mock log: session_start, turn log, user_prompt  — and no tool_use request, because no tool ran
```

That is correct extension behaviour and is itself evidence for HOOK-05, but it means **no
tool-call row can be driven by a natural-language prompt while the mock is in `deny` mode**. In
production the two are independent engines — a command-block policy pack does not deny prompts — so
the uniform mock is the artificial part, not the extension. Consequences for `docs/SMOKE.md`:

- Rows 7, 8 (`!cmd` / `!!cmd`) are unaffected: a shell escape is `user_bash` and never reaches the
  `input` handler.
- Row 10 (prompt denied) is exactly this behaviour.
- Rows 12 and 17 need a mode that denies tool calls while allowing prompts, which the mock does not
  have. Recorded as a follow-up in `docs/SMOKE.md`; the parts of those rows that can be verified
  another way were, and are recorded there.

---

## Intentional parity gaps

Everything below is shipped knowingly. Each row names the owner: **this phase** (accepted, recorded,
no further work), **Phase 10**, or **product** (a decision outside engineering's gift).

| # | Gap | Why it exists | Consequence | Owner |
|---|---|---|---|---|
| 1 | **Tool-output DLP cannot fire for pi** | HOOK-06 sends a `content_sha256` + `content_bytes` digest, never the output. `audit_service.py:113-139` serialises the whole `tool_use` array *including* `tool_response` and feeds that to DLP, so there is nothing for DLP to match on | A secret appearing in a tool result is invisible to DLP on this path. A direct consequence of the locked requirement, not a defect (T-09-25, accepted) | product |
| 2 | **Assistant text is never sent** | The turn record holds no assistant text; `messages[1].content` is the empty string. `agent_end.messages` does carry it, but forwarding it would be new egress no requirement asked for | Model output is not DLP-scanned on this path | product |
| 3 | **A prompt template's expanded body is never checked** | `agent-session.js:1229` emits `input` *before* skill/template expansion, so `/name args` arrives as the literal text the user typed | The text is checked as typed; whatever the template expands to is not. Recorded in `prompt.ts`'s header | product |
| 4 | **Slash commands never reach the `input` handler** | Built-ins (`/help`, `/new`, `/compact`, `/reload`, `/fork`, `/resume`, …) are intercepted in the TUI before `session.prompt()` (`interactive-mode.js:2440-2586`); an extension `/cmd` is dispatched by `_tryExecuteExtensionCommand` before `_runInputHandlers` (`agent-session.js:1217-1224`) | Not promptable-content, so not a policy surface — but an unmatched `/typo` *does* arrive, as plain text | this phase |
| 5 | **pi is enforced by neither budgets nor spend limits** | pi is in neither `BUDGET_ENFORCED_APP_LABELS` nor `SPEND_LIMIT_ENFORCED_APP_LABELS` (`preToolUseHandler.ts:1480,1490-1495`) | A pi user's spend is recorded but never blocked on. Adding the label is a one-line API change once someone decides pi should be in scope | product |
| 6 | **`user_bash` does not set `pull_policies`** | The `!cmd` payload is specified as `toolName: "bash"`, `toolInput: {}` with no refresh flag (09-03) | A session that only ever used `!cmd` never refreshes `tools_to_check`, so native file tools are never cache-skipped and always round-trip. Degrades toward *more* requests, never toward a skipped check | this phase |
| 7 | **A truncated prompt carries a shell-comment-shaped marker** | `buildPromptPayload` reuses `capCommand` so there is one implementation of the both-ends padding-bypass rule; its marker is `\n#...unbound: omitted...\n` | In the middle of natural-language text the marker reads as a shell comment. Cosmetic; the alternative was a second capper to keep in sync | this phase |
| 8 | **The bypass class** | `pi --no-extensions`, `PI_CODING_AGENT_DIR` pointing at a clean install, and an SDK embedder setting `noExtensions` all run pi with no policy checking at all | Enforcement is advisory against a user who controls their own machine. Closing it needs MDM-managed settings, not extension code | Phase 10 |
| 9 | **A heartbeat cannot warm `tools_to_check`** | `handleGuardrails` omits the tool list by design (`preToolUseHandler.ts:1399-1405`) and the empty-`tool_name` path omits it too (`:1008-1012`); faking `tool_name: "ls"` was rejected because it can fire a Slack approval for a call that never happened | The first real tool call of a process always round-trips. Needs a first-class `session_start` branch in the API returning `computeToolsToCheck` | Phase 7 / API |
| 10 | **`'auto'` as the turn-log model is unverified** | Assumption A1: every Python hook uses `'auto'` and those turn logs produce rows, so `'auto'` is inferred to be an enabled global `AIModel` | If it is not, every `/v1/hooks/pi` row is silently dropped (`add_gateway_metrics_task.py:573-577`) and RES-04 is unproven. **Still unverified** — it needs one staging curl, and staging does not yet run Phase 7 | Phase 7 / API |

---

## Metadata

- Run 2026-09-27 (UTC) against pi `0.87.1`, Node `v22.22.2`, bundle `dist/pi/index.js` 52 771 bytes.
- Spike teardown: `~/.pi/agent/extensions/zz-spike` removed; `~/.pi/agent/.unbound/policy_cache.json`
  cleared between runs; `~/.unbound/config.json` never touched.
- Recipe source: `09-RESEARCH.md` §D3, run as written except for the `--mode allow` substitution in
  Spike A, explained above.
