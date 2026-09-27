# Manual smoke tests — pi extension

Two recipes. The **mock-API smoke** is always runnable and needs no Unbound
infrastructure. The **staging smoke** proves the end-to-end path and is gated
on the Phase 7 API/backend changes being merged and deployed.

Tested against: pi `0.87.1`, Node `v22.22.2`. `dist/pi/index.js` was 18160 bytes for the Phase 8
rows (1–6), then 18945 bytes after the three review fixes (trimming the resolved API key, keeping
the tail of an over-long command, and refusing a non-absolute home dir) — the behaviour of rows 1–6
is unchanged by either. Rows 7–17 were run against the Phase 9 bundle, **52 771 bytes**, which adds
the file tools, the user shell escape, prompt checking, the tool-result audit, the turn log, the
session heartbeat, the 300 s policy cache, the circuit breaker and the revoked-key latch.

---

## 1. Mock-API smoke in the real pi TUI

Setup (done by the executor before the human runs pi):

```bash
cd setup/hooks-ts
npm run build
mkdir -p ~/.pi/agent/extensions/unbound
cp dist/pi/index.js ~/.pi/agent/extensions/unbound/index.js
ls ~/.pi/agent/extensions/unbound/index.ts   # must NOT exist — index.ts shadows index.js
npm run mock-api -- --mode deny --port 8799   # background; modes: deny | ask | hang | allow …
curl -s -XPOST http://127.0.0.1:8799/v1/hooks/pretool -d '{}'
# → {"decision":"deny","reason":"Reading secrets is blocked."}
```

Strings as they appear verbatim in the built file (compare against the TUI):

| Situation | Exact text |
|---|---|
| deny prefix | `Blocked by Unbound policy: ` |
| deny, no reason from API | `Blocked by Unbound policy.` |
| confirm title | `Unbound policy` |
| confirm body suffix | `\n\nRun this command?` |
| user picked No / dismissed / timed out | `Declined by user (Unbound policy)` |
| ask while headless (`pi -p`, json) | `Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.` |
| API failure after a remembered `policy_check_failure_action: block` | `Unbound policy engine unavailable — please retry` |
| no API key at `session_start` | `Unbound: no API key found — extension inactive` |
| **Phase 9 —** breaker opens after repeated failures | `Unbound policy engine unreachable — allowing tool calls for 60 s` |
| **Phase 9 —** key rejected (401/403) enough times | `Unbound: API key rejected — enforcement inactive` |
| **Phase 9 —** a blocked prompt (`input`) | the same `Blocked by Unbound policy: ` prefix, raised at `error` level so the notification is **red** |
| **Phase 9 —** `tool_use_id` of a `!cmd` / `!!cmd` | prefix `ubash_` + 20 hex characters (`ubash_` + `randomBytes(10)`), e.g. `ubash_6f1c…`; native tool calls keep pi's `call_…` format |

Steps and expected outcome. `pi` is started as
`UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test pi`
unless stated otherwise. Ask pi to run `echo hi` each time.

| # | Mock mode | Command | Expected | Observed (human, verbatim) | Result |
|---|---|---|---|---|---|
| 1 | `deny` | `pi` (TUI) | tool does not run; error tool-result `Blocked by Unbound policy: Reading secrets is blocked.` + red notification | Human (Sumit), 2026-09-26: "1 - pass" | ✅ |
| 2a | `ask` | `pi` (TUI) → pick **No** | Yes/No overlay titled `Unbound policy`, body has `Unusual command.` + `Run this command?`, countdown visible; transcript shows `Declined by user (Unbound policy)` | Human (Sumit), 2026-09-26: "2 - pass" | ✅ |
| 2b | `ask` | `pi` (TUI) → pick **Yes** | command runs | Human (Sumit), 2026-09-26: "2 - pass" | ✅ |
| 3 | `hang` | `pi -p --mode json` (headless, run by the executor at the human's request) | ~20 s pause, then the command runs (bounded fail-open, never indefinite) | `tool_execution_start` at t+2 s → `tool_execution_end` at t+22 s (exactly 20 s), result `hi\n`, `isError:false`. Repeated on a retry: t+23 s → t+43 s. Bounded, then ran. | ✅ |
| 4 | `ask` | `pi -p --mode json "…echo hi…"` | blocked with the headless reason, no dialog | `tool_execution_end … "text":"Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.", "isError":true`; `toolCallId` = `call_qpLNCvyocPYU1AzKXBmLtmVl` (pins assumption A2: pi's `call_…` id format). In plain `-p` text mode the model paraphrased the same reason. | ✅ |
| 5 | `deny` | `pi -p --mode json --no-extensions` | runs, no Unbound involvement | result `hi\n`, `isError:false`; mock logged **no** pretool request | ✅ |
| 6 | `deny` | both env keys unset, `~/.unbound/config.json` moved aside, `pi -p --mode json` | one `Unbound: no API key found — extension inactive` notice; command runs; never a block. **Restore config.json afterwards** | result `hi\n`, `isError:false` with the mock in **deny** mode — proves the extension was inactive; mock logged **no** pretool request (the single logged request was the operator's `curl` sanity check). The notice itself is swallowed in `-p` mode (§A6) so it was not observable headlessly. `config.json` restored, `cmp` byte-identical to the pre-move copy. | ✅ |

Steps 3–6 were run headless by the executor because the human ran out of interactive time after steps 1–2; `-p --mode json` exposes the raw tool result, which is stronger evidence than the rendered TUI for those four cases. Model used for the headless runs: `openrouter/openai/gpt-4.1-nano` (the default Anthropic provider was out of usage). Mock stopped afterwards; port 8799 free.

If nothing happens at all, first look for a startup line
`Failed to load extension "…": …` — that is a load failure, not a policy outcome.

To switch modes: stop the mock (`kill <pid>`) and restart with `--mode <mode>`.

### Rows 7–17 — the Phase 9 event surface

Setup, in addition to the block above (the executor does all of this before the human starts):

```bash
cd setup/hooks-ts
npm run build
cp dist/pi/index.js ~/.pi/agent/extensions/unbound/index.js
cmp -s dist/pi/index.js ~/.pi/agent/extensions/unbound/index.js   # must exit 0
test ! -e ~/.pi/agent/extensions/unbound/index.ts                 # index.ts shadows index.js
rm -f ~/.pi/agent/.unbound/policy_cache.json                      # between rows that touch the cache
npm run mock-api -- --mode deny --port 8799
curl -s -XPOST http://127.0.0.1:8799/v1/hooks/pretool \
  -H 'content-type: application/json' \
  -d '{"pre_tool_use_data":{"tool_name":"bash","command":"x","metadata":{}}}'
# → {"decision":"deny","reason":"Reading secrets is blocked."}
```

Two setup facts that did not apply to rows 1–6:

- **A bare `-d '{}'` is no longer a valid deny smoke.** The mock models the server's Path-2 entry
  gate, so a body carrying neither a command nor a `metadata.file_path` answers
  `{"decision":"allow","_entry_gate":"no_evaluable_input"}` whatever `--mode` says. Send a body with
  a command, as above.
- **`--mode deny` denies the prompt too**, and the prompt check runs before the model is invoked, so
  in `deny` mode no tool call of any kind ever happens from a typed prompt. That is correct extension
  behaviour (it is row 10), but it makes rows 12 and 17 unrunnable as originally written; see
  `docs/SPIKES.md` → "A note on mock modes" and the follow-up under the table.
- **Headless runs need stdin closed.** `pi -p … < /dev/null`; without it pi waits on stdin forever
  and the run looks hung. Model for every headless run: `openrouter/openai/gpt-4.1-nano`.

Mode order that minimises restarts: `deny` (rows 7, 8, 10) → `allow` (rows 9, 11, 14, 15) →
`toolsEmpty` (row 13) → `hang` (row 16).

| # | Mock mode | Command | Expected | Observed | Result |
|---|---|---|---|---|---|
| 7 | `deny` | in the TUI, type `!cat .env` | the command does **not** run; the bash block shows `Blocked by Unbound policy: Reading secrets is blocked.` with a non-zero exit, and the text is in the transcript | Executor via `pi --mode rpc` (same `emitUserBash` → `recordBashResult` path the TUI uses), 2026-09-28, mock `deny`: `{"id":"r7","type":"bash","command":"cat .env"}` → `{"output":"Blocked by Unbound policy: Reading secrets is blocked.","exitCode":1,"cancelled":false,"truncated":false}`; no `bash_execution_update` (command never ran); mock logged one pretool | ✅ PASS (executor, rpc) |
| 8 | `deny` | in the TUI, type `!!cat .env` | the same block, and the output is **excluded from the model's context** (still visible to the human) | Executor via `pi --mode rpc`, 2026-09-28, mock `deny`: `{"id":"r8","type":"bash","command":"cat .env","excludeFromContext":true}` → identical four-key block result, `exitCode:1`; pi's `recordBashResult(..., {excludeFromContext:true})` handles the context exclusion | ✅ PASS (executor, rpc) |
| 9 | `allow` | in the TUI, type `!echo hi` | runs normally; the mock logs one pretool with `tool_name: "bash"` and a `ubash_…` `tool_use_id` | Executor via `pi --mode rpc`, 2026-09-28, mock `allow`: `!echo hi` → `bash_execution_update` delta `hi\n`, result `{"output":"hi\n","exitCode":0}`; mock logged one pretool for the call (the `ubash_` id format is locked by `userBash.test.ts`) | ✅ PASS (executor, rpc) |
| 10 | `deny` | in the TUI, type the prompt `read my .env` | the prompt never reaches the model (no assistant turn starts) and exactly one **red** notification carries the reason | Executor, headless, 2026-09-27: `pi -p --mode json … "Call the spike_echo tool…"` printed `Blocked by Unbound policy: Reading secrets is blocked.` on stderr and exited 0. The mock logged `session_start`, a turn log and `user_prompt` — and **no** `tool_use` request, because the model was never invoked. The notification is raised at `error` level (`prompt.ts:106`), which is what makes it red; the colour itself is the human's remaining check | ✅ PASS (executor, headless + rpc) — rpc 2026-09-28: `{"type":"prompt","message":"read my .env"}` produced `extension_ui_request method:"notify" notifyType:"error"` (red) with the reason and NO `agent_start`/`message_start`; the model was never engaged |
| 11 | `allow` | in the TUI, type any prompt | it reaches the model **unchanged** — no added prefix or suffix | Executor, headless, 2026-09-27: the turn log for the run carried `messages[0].content` as the exact prompt typed — `"Call the spike_echo tool with text=hello, then read the file package.json."` — with nothing prepended or appended, and the model answered normally | ✅ PASS (executor, headless) |
| 12 | `deny` | ask pi to `read package.json` | blocked; the mock body shows `command: ""`, a `metadata.file_path` ending `package.json`, and **no** `tool_input.content` | Executor, 2026-09-27, in `--mode allow` (see the caveat above — in `deny` mode the prompt is blocked first, so the file tool is never called). The wire body was exactly as required: `{"tool_name":"read","command":"","metadata":{"cwd":"…/hooks-ts","tool_input":{"path":"package.json"},"file_path":"package.json"},"tool_use_id":"call_zlrog0GAptWLf5DoDCqA18cx"}` — `tool_input` carries only `path`, no `content`; `event_name` `tool_use`; `pull_policies: true` on this first real tool call. The **deny rendering** for a file tool was not exercised: it is the same `Blocked by Unbound policy: ` path as row 1, already verified in Phase 8 | ⚠️ PARTIAL — wire body PASS (executor); deny rendering carried by row 1 |
| 13 | `toolsEmpty` | ask pi to `grep TODO`, then ask again | the **second** file-tool call makes zero HTTP requests (the mock's request count is unchanged) | Executor, headless, 2026-09-27, cache cleared first. pi made **two** file-tool calls (`read` twice — the nano model chose `read` over `grep`), and the mock received **zero** `tool_use` requests for either: the only traffic was `session_start`, two turn logs and one `user_prompt`. Stronger than expected, and for a reason worth recording: this mock answers *every* pretool with `tools_to_check: []`, including the `session_start` heartbeat, so the cache was warmed before the first file tool. The real API omits the tool list for `session_start` (gap 9 in `docs/SPIKES.md`), so in production the first call round-trips and only the second is skipped. Cache on disk afterwards: `0600`, `{"tools_synced_at":…,"tools_to_check":[],"gateway_url":"http://127.0.0.1:8799","key_fingerprint":"sha256:9f86d081884c7d65"}` — a fingerprint, never the key | ✅ PASS (executor, headless) |
| 14 | `allow` | finish one turn | nothing visible; the mock logs one `POST /v1/hooks/pi` with `model: "auto"`, a user + assistant message, `tool_use[]`, and **no** raw tool output anywhere in the body | Executor, headless, 2026-09-27: `POST /v1/hooks/pi` with `"model":"auto"`, `messages[0]` the user prompt, `messages[1]` the assistant with `tool_use:[{"type":"PostToolUse","tool_name":"read","tool_use_id":"call_zlrog…","tool_input":{},"tool_response":{"content_sha256":"06677b4321e1e7d67894e44fe9c92b9c817aa0c4496c5b3d0769350029317d19","content_bytes":899}}]` — a digest and a byte count, not one byte of the 899-byte file. Note **two** turn logs per invocation, not one: `agent_end` fires more than once (RESEARCH §F3), and the first carries an empty user message and an empty `tool_use[]` | ✅ PASS (executor, headless) |
| 15 | `allow` | start pi, then `/new`, then `/new` again | nothing visible; **exactly one** heartbeat pretool with `pull_policies: true` and `client_entrypoint: "pi/0.87.1"` | Executor, headless, 2026-09-27: every invocation produced exactly **one** `event_name: session_start` request, with `pull_policies: true`, `unbound_app_label: "pi"`, `client_entrypoint: "pi/0.87.1"` and `metadata` of `cwd, has_ui, pi_version` only. Confirmed across five separate processes, and the nested-pi spike shows a child process getting its own single heartbeat under a different `conversation_id`. The `/new` ×2 case is TUI-only and still needs the human: `session_start` fires on `/new` (§F4), so the assertion there is that the *second* and *third* fire produce no additional heartbeat | ✅ PASS — rpc 2026-09-28: one process, `new_session` ×2 then a second `!echo`; mock logged exactly ONE heartbeat pretool + ONE `/v1/hooks/pi` presence POST, then one pretool per bash call — `/new` added nothing |
| 16 | `hang` | ask pi to run four bash commands | the first three each pause about 20 s, then the breaker opens — the remaining calls return immediately and one notice reads `Unbound policy engine unreachable — allowing tool calls for 60 s` | Executor, headless, 2026-09-27, cache cleared first. Whole run 69 s wall clock (10:31:59 → 10:33:08 UTC) for what would have been 6 × 20 s = 120 s unbroken. The mock received exactly four pretool attempts — `session_start`, `user_prompt`, `bash "echo a"`, `bash "echo b"` — plus **one** `POST /v1/hooks/errors` self-report of the bypass, and then nothing: every later bash call made zero HTTP. stderr carried exactly one notice, verbatim: `Unbound policy engine unreachable — allowing tool calls for 60 s`. All four commands ran (`a`, `b`, `c`, `d` all present in the results); nothing hung indefinitely. Note `echo a` and `echo b` were both in flight before the breaker tripped because pi issues a tool batch concurrently, so the "first three" of the expectation is "the first few concurrent attempts", not a strict count | ✅ PASS (executor, headless) |
| 17 | `deny` | headless: `UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test pi -p --mode json --model openrouter/openai/gpt-4.1-nano "run: echo hi" < /dev/null` | blocked with the reason in the output, no dialog, no crash, no stack trace | Executor, headless, 2026-09-27: the headless deny path was exercised and behaved — `Blocked by Unbound policy: Reading secrets is blocked.` on stderr, exit code 0, no dialog, no throw, no stack trace. It blocked on the **prompt** (`user_prompt`) rather than on the bash call, because in `deny` mode the prompt check fires first and the model is never invoked, so no `bash` tool call is reachable. The bash-path variant of this row needs a mock mode that denies tool calls while allowing prompts | ⚠️ PARTIAL — headless deny PASS on the prompt path; bash path blocked by the mock's uniform mode |

**Follow-up (mock, Wave 0 sized):** add a mode that denies `tool_use` while allowing `user_prompt`
— e.g. `denyTools` — so rows 12 and 17 can be run as written. The real API evaluates prompts and
commands through independent engines, so a uniform-deny mock is the artificial part here: an
organisation with a command-block pack and no prompt policy is the normal configuration, and the
mock currently cannot express it.

---

## 2. Staging end-to-end smoke (gated on Phase 7)

Host: `https://api-gateway-staging.unboundsecurity.ai`
(`api-staging.getunbound.ai` is **NXDOMAIN** — do not use it.)

Gate check run 2026-09-25 (UTC):

```
gh pr view 969  --repo websentry-ai/ai-gateway      --json state,mergedAt  → {"mergedAt":null,"state":"OPEN"}
gh pr view 2947 --repo websentry-ai/ai-gateway-data --json state,mergedAt  → {"mergedAt":null,"state":"OPEN"}
curl -s -o /dev/null -w '%{http_code}' https://api-gateway-staging.unboundsecurity.ai/health → 200
```

Gate re-checked for the Phase 9 smoke, 2026-09-27 (UTC) — unchanged:

```
gh pr view 969  --repo websentry-ai/ai-gateway      --json state,mergedAt  → {"mergedAt":null,"state":"OPEN"}
gh pr view 2947 --repo websentry-ai/ai-gateway-data --json state,mergedAt  → {"mergedAt":null,"state":"OPEN"}
gh pr view 349  --repo websentry-ai/setup           --json state,mergedAt  → {"mergedAt":null,"state":"OPEN"}
curl -s -o /dev/null -w '%{http_code}' https://api-gateway-staging.unboundsecurity.ai/health → 200
```

**STAGING SMOKE: SKIPPED — Phase 7 not deployed** (Phase 9 verdict, 2026-09-27). The host is up but
does not run the Phase 7 code, so nothing on it can prove pi attribution. One consequence is
load-bearing beyond attribution: **assumption A1 — that `'auto'` is an enabled global `AIModel` —
remains unverified**, so RES-04's turn log is proven only as far as the request on the wire (row 14).
If `'auto'` does not resolve, every `/v1/hooks/pi` row is silently dropped
(`add_gateway_metrics_task.py:573-577`). The confirming curl is carried in `09-PR-LINKS.md`.

The Phase 8 verdict below, for the same reason, still stands:

**STAGING SMOKE: SKIPPED — Phase 7 not deployed.** Both Phase 7 PRs are open
and unmerged, so a `pi`-labelled pretool request on the deployed build may be
relabeled by `KNOWN_APP_LABELS`; attribution cannot be proven yet. A keyless
`POST /v1/hooks/pretool` returning `{"decision":"allow"}` is NOT deployment
evidence — that branch returns before the label is inspected.

Checklist to run once #969 and #2947 are merged and ArgoCD-deployed:

1. `unbound status` → logged in, Role Admin, API Connected. Note the gateway URL.
2. `unbound policy tool families` → pick a valid command family + field name.
3. Create a BLOCK policy scoped to a **single-user test group**:
   `unbound policy tool create-terminal --name "Phase-8 smoke — block rm -rf /tmp/x" --command-family <family> --field <key>=<pattern> --action BLOCK --custom-message "Blocked for the Phase-8 smoke test." --group "<single-user-test-group>" --json`
   — capture the policy id.
4. The gateway caches policies for ~5 minutes — wait it out.
5. `cp ../pi/index.js ~/.pi/agent/extensions/unbound/index.js` (or rebuild first
   with `npm run build && cp dist/pi/index.js ~/.pi/agent/extensions/unbound/index.js`), then
   `UNBOUND_GATEWAY_URL=https://api-gateway-staging.unboundsecurity.ai UNBOUND_PI_API_KEY=<application API key for a TEST org> pi`
   and ask pi to run `rm -rf /tmp/x`. Expect the deny with the custom message
   after `Blocked by Unbound policy: ` (+ `Enforced by Unbound · Trace ID …` footer if attribution is on).
   The key is an **application API key**, not the `unbound login` token.
6. Confirm in the staging console / `GatewayMetrics` that the row is attributed to **`pi`**
   (`app_label='pi'`, `source='hooks'`) — that, not the 200, is the HOOK-01 evidence.
7. Confirm the audit row's `tool_use_id` is pi's `toolCallId` format.
8. **Always clean up:** `unbound policy tool delete <policy-id>`.

Never record the staging key, token, or any customer identifier in this file.
