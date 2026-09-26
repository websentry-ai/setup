# Manual smoke tests — pi extension

Two recipes. The **mock-API smoke** is always runnable and needs no Unbound
infrastructure. The **staging smoke** proves the end-to-end path and is gated
on the Phase 7 API/backend changes being merged and deployed.

Tested against: pi `0.87.1`, Node `v22.22.2`, `dist/pi/index.js` = 18160 bytes.

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
