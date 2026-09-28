// Every literal Phase 8 depends on, in exactly one place.
//
// RESEARCH assumption A3: `UNBOUND_PI_API_KEY` (and every other user-visible string) lives here so
// Phase 9's handlers and Phase 10's `setup/pi/setup.py` installer import the same value instead of
// re-typing it. Nothing in this file imports anything.

// --- Environment variables (naming precedent: RESEARCH §C3) ---------------------------------
export const ENV_API_KEY_PI = "UNBOUND_PI_API_KEY";
export const ENV_API_KEY_GENERIC = "UNBOUND_API_KEY";
export const ENV_GATEWAY_URL = "UNBOUND_GATEWAY_URL";
/** Exported by pi's managed-install launcher; its `current-version` file holds the pi version (§A8). */
export const ENV_PI_INSTALL_ROOT = "PI_MANAGED_INSTALL_ROOT";

// --- Hosts, paths, identity ------------------------------------------------------------------
/** unbound-cli `src/config.js:9` DEFAULT_GATEWAY_URL. */
export const DEFAULT_GATEWAY_URL = "https://api.getunbound.ai";
export const CONFIG_DIR_NAME = ".unbound";
export const CONFIG_FILE_NAME = "config.json";
/**
 * The policy cache lives beside pi's own install, not in `~/.unbound`: `<agent dir>/.unbound/
 * policy_cache.json`. Same literal as `CONFIG_DIR_NAME`, deliberately a separate constant — the two
 * have different parents and relocating one must not move the other.
 */
export const CACHE_DIR_NAME = ".unbound";
export const CACHE_FILE_NAME = "policy_cache.json";
/** `join(homedir(), ...)` — pi's default agent dir, `PI/dist/config.js:405-427`. */
export const PI_AGENT_DIR_SEGMENTS = [".pi", "agent"] as const;
/** pi's own relocation hook, tilde-expanded, takes precedence over the default (§A6). */
export const ENV_PI_AGENT_DIR = "PI_CODING_AGENT_DIR";
/** The cache is keyed on a digest, never on the key. See `keyFingerprint` (T-09-14). */
export const KEY_FINGERPRINT_PREFIX = "sha256:";
/** `unbound_app_label` on the wire; `'pi'` joined the union in Phase 7. */
export const APP_LABEL = "pi";
/** `hook_source` on POST /v1/hooks/errors — the label rides this field, there is no app label there. */
export const HOOK_SOURCE = "pi";
export const EVENT_NAME_TOOL_USE = "tool_use";
/**
 * RES-05's `event_name`. It lands on `preToolUseHandler.ts:1008-1012` — the fall-through for an
 * unrecognised event with a blank `tool_name` — which answers a `no_policy` allow carrying
 * `policy_check_failure_action` and **no `tools_to_check`** (§C2). That is the intended outcome: the
 * heartbeat warms the fail-open opt-out and announces the extension, and the tool list is pulled on
 * the first genuine tool call instead. Never send a `tool_name` here — a synthetic `ls` reaches
 * `handleCommandPolicy` and can fire a real Slack approval for a call nobody made (T-09-20).
 */
export const EVENT_NAME_SESSION_START = "session_start";
/**
 * The one-line switch from RESEARCH Open Question 1.
 *
 * A pretool heartbeat leaves only a Sentry span tag (`preToolUseHandler.ts:220`), so "the backend can
 * tell the extension is present" is not durably true from it alone. One minimal `/v1/hooks/pi` POST
 * creates a `GatewayMetrics` row with `app_label='pi'`, which is. Set this to `false` to drop the
 * durable row and keep the heartbeat; `heartbeat.test.ts` is written to pass either way, so flipping
 * it needs no test edit. Bounded by `derive_hook_request_id` collapsing identical empty turns into one
 * row per session.
 */
export const SESSION_PRESENCE_ROW_ENABLED = true;
/**
 * HOOK-05's `event_name`. Matched server-side at `preToolUseHandler.ts:655`, which routes to
 * `handleGuardrails` — the one branch that can deny a prompt, and the one that deliberately omits
 * `tools_to_check` from its response so a prompt check cannot clobber the tool cache (§C2).
 */
export const EVENT_NAME_USER_PROMPT = "user_prompt";
/**
 * `UserBashEvent` carries no id of its own (`types.d.ts:710-719`), so HOOK-04 mints one per typed
 * command. Namespaced so a `tool_use_id` in the gateway's audit trail is traceable to a human
 * keystroke rather than to a model decision.
 */
export const USER_BASH_ID_PREFIX = "ubash_";
export const PRETOOL_PATH = "/v1/hooks/pretool";
export const ERRORS_PATH = "/v1/hooks/errors";
/**
 * The turn log (RES-04). `piHandler` is registered here and at `/hooks/pi`; unlike pretool, a missing
 * `Authorization: Bearer` is a hard 401 (`hooksHandlerFactory.ts:46-50`).
 */
export const TURNLOG_PATH = "/v1/hooks/pi";
/**
 * **The turn log's `model` is this literal, not `ctx.model?.id`. Do not "improve" it.**
 *
 * `add_gateway_metrics_task.py:565-577` runs `check_valid_record` and returns early on
 * `"Model Not found"` — silently, with no row created. The `add_new_model` path that would register
 * an unknown id runs only for proxy requests (`:555-557`), and hook telemetry is not one. So sending
 * a real id such as `openrouter/openai/gpt-4.1-nano` usually means **the turn is never recorded at
 * all**. `'auto'` is the fallback every Python hook uses (`unbound.py:4983`) and is listed in
 * `PROXY_FALLBACK_MODEL_NAMES` (`proxy_service.py:62`).
 *
 * The real model id is still available server-side on the proxy path, and on `agent_end`'s messages
 * for anyone who later wants it — losing it here costs analytics nothing and buys every row.
 */
export const TURNLOG_MODEL = "auto";
/** The `tool_use[]` entry discriminator the backend's reader expects (`PY:4888-4896`). */
export const TURNLOG_TOOL_USE_TYPE = "PostToolUse";

// --- Timeouts (RESEARCH §F5: an unbounded confirm hangs the whole tool batch) -----------------
export const PRETOOL_TIMEOUT_MS = 20_000;
export const ERRORS_TIMEOUT_MS = 10_000;
/**
 * The turn-log deadline, locked by 09-CONTEXT and matching the Python hook's 10 s curl timeout
 * (`PY:5010-5041`). It bounds the REQUEST, not the handler: `agent_end` returns synchronously and the
 * POST finishes on its own, so this is how long a socket may stay open, never how long pi waits.
 */
export const TURNLOG_TIMEOUT_MS = 10_000;
export const CONFIRM_TIMEOUT_MS = 120_000;
/** One bypass self-report per minute, per `unbound.py`'s convention (§B7). */
export const ERROR_REPORT_INTERVAL_MS = 60_000;
export const ERROR_CATEGORY_BYPASS = "bypassed_due_to_failure";
/**
 * WR-03. A fail-CLOSED failure was blocked, not bypassed, and `message.slice(0,100)` is the Sentry
 * fingerprint (§B6) — so filing both under one category makes the "enforcement was silently skipped"
 * alert fire for the customers who explicitly paid for fail-closed and got it. `category` is a free
 * string server-side (`hookErrorHandler.ts:55-87`), so this needs no API change.
 */
export const ERROR_CATEGORY_BLOCKED = "blocked_due_to_failure";
/**
 * The third outcome, and neither of the first two: `POST /v1/hooks/pi` failed, so an audit row was
 * lost. No policy check was skipped and none was blocked — enforcement already happened, on the
 * pretool path, minutes earlier.
 *
 * It needs its own category because both of the above feed the "enforcement was silently skipped"
 * alert, and this route is the *most* likely of the three to fail: it 404s entirely until the Phase 7
 * backend ships. Filing lost rows there would bury every genuine fail-open event under noise from a
 * route that enforces nothing. `category` is a free string server-side (`hookErrorHandler.ts:55-87`),
 * so an honest third label costs no API change.
 */
export const ERROR_CATEGORY_TURNLOG = "turn_log_failed";

// --- The revoked-key latch (WR-01) ------------------------------------------------------------
/**
 * Consecutive 401/403 responses that deactivate the session. Two, not one: a single rejection can be
 * a deploy blip or a race with a key rotation, and a session-long enforcement shutdown is too big a
 * consequence for one transient status.
 */
export const KEY_REJECTION_THRESHOLD = 2;

// --- The circuit breaker (WR-02) --------------------------------------------------------------
/** Consecutive `ok:false` results that take the gateway out of circuit for `BREAKER_OPEN_MS`. */
export const BREAKER_FAILURE_THRESHOLD = 3;
/**
 * How long the breaker stays open. The open notice below states this window in words, so the two
 * must be changed together — a notice promising 60 s while the window is 5 min would be a lie.
 */
export const BREAKER_OPEN_MS = 60_000;
/**
 * Policy-cache freshness window. `unbound.py:70 CACHE_TTL_SECONDS = 300`, in milliseconds so it can
 * be compared against `Date.now()` without a unit conversion at every call site.
 *
 * It bounds `tools_synced_at` only. `policy_check_failure_action` is read **regardless** of age
 * (`unbound.py:225`): an org's opt-out from fail-open must not silently lapse into fail-open just
 * because the last successful response was six minutes ago.
 */
export const CACHE_TTL_MS = 300_000;

// --- Caps (V5 / T-08-06) ---------------------------------------------------------------------
export const MAX_REASON_CHARS = 2000;
/**
 * The largest `policy_cache.json` that is opened at all (CR-01 / WR-01).
 *
 * Two jobs. The obvious one is a byte cap on untrusted external data, matching the convention the S3
 * catalog reader already follows. The load-bearing one is that having a cap at all is what forces the
 * `lstat`-before-`read` in `safeRead.ts`: the size question cannot be asked without a stat, and the
 * stat is what refuses a FIFO — the shape that makes `readFileSync` block forever rather than throw.
 *
 * 64 KiB against a real record of a few hundred bytes. `MAX_TOOLS_TO_CHECK` × `MAX_TOOL_NAME_CHARS`
 * is ~32 KiB of `tools_to_check` in the worst case the writer can produce, so the cap is above
 * anything this extension writes and far below anything worth parsing.
 */
export const MAX_CACHE_BYTES = 65_536;
/**
 * The most entries a `tools_to_check` may carry, and the longest one name may be (WR-01).
 *
 * The taxonomy has six entries, so 256 × 64 is generous by two orders of magnitude and still bounds
 * what one response can make this process hold for a session and write to disk every session after.
 *
 * An OVER-CAP list is refused whole, not truncated, and that asymmetry is deliberate. A truncated
 * list is a *wrong* list: dropping the entry that names the one tool an org does have a policy for
 * turns `shouldSkipFileTool` into a skip, which is a silently disabled check. Refusing the whole
 * field means "never learned" — the state that costs a round trip per call and enforces on every one.
 * Junk entries *inside* a within-cap list are still dropped individually, because there the effect
 * only ever narrows the skip set.
 */
export const MAX_TOOLS_TO_CHECK = 256;
export const MAX_TOOL_NAME_CHARS = 64;
/**
 * The same guard for `~/.unbound/config.json` (CR-01). Separate constant, larger value: the config
 * file is shared with unbound-cli and six other tools, so it may legitimately carry keys this
 * extension never reads, and a cap that refused a file the CLI wrote would silently unset identity —
 * i.e. an inert extension. 256 KiB is far above any credential file and still bounds the read.
 */
export const MAX_CONFIG_BYTES = 262_144;
/**
 * HOOK-06's bail-out: the largest canonical content projection that is actually hashed (§F7).
 *
 * `tool_result` is an **awaited** pass over every tool result (`agent-session.js:265-294` gates it
 * on `hasHandlers`), so the hash sits on the path between a tool finishing and the model seeing its
 * output. A `read` of a 100 MB file must not buy a sha256 of 100 MB there; above this cap the record
 * keeps the byte count, sets `hash_skipped` and hashes nothing. 4 MB is far above any real tool
 * output and far below anything a developer would feel.
 */
export const MAX_HASH_BYTES = 4_194_304;
/**
 * The most tool results one turn record retains. A backstop, not a budget: `tool_result` fires once
 * per result with no ceiling on how many a turn can produce, and the record lives until `agent_end`,
 * so this array could otherwise grow without limit — a long agentic turn, or any state where nothing
 * drains the record, would hold every entry.
 *
 * 500 is far above any real turn (a `tool_use` array that long is already an unreadable audit row)
 * and far below anything that costs memory. Past it the OLDEST entries go and `results_truncated`
 * counts them, because a row that quietly described 500 of 600 results would look complete.
 *
 * This comment used to call `results` "the one part of `turn.ts` that could otherwise grow without
 * limit", which was wrong in the most misleading possible way: `tool_calls` had no cap at all, and a
 * clearer unbounded path. See `MAX_TURN_TOOL_CALLS`.
 */
export const MAX_TURN_RESULTS = 500;
/**
 * The same backstop for `tool_calls` (WR-04), and the path that made it necessary is not
 * hypothetical: `user_bash` records a tool call, and pi fires no `agent_end` for a bare `!cmd`
 * (RESEARCH §F3), so nothing calls `take()` and that entry lives for the whole session.
 *
 * Same value and same drop-oldest discipline as `MAX_TURN_RESULTS`, counted by
 * `tool_calls_truncated`. The two are separate constants because they bound different events with
 * different producers — retuning one must not silently retune the other.
 */
export const MAX_TURN_TOOL_CALLS = 500;
export const MAX_TOOL_INPUT_BYTES = 16_384;
export const MAX_COMMAND_CHARS = 8192;
/**
 * The prompt-body cap (HOOK-05). Same value as `MAX_COMMAND_CHARS` and the same rationale: **both
 * ends are kept**, because head-only truncation is a padding bypass. A prompt-injected or careless
 * paste can put 8 KB of innocuous prose first and the instruction that matters last, and a guardrail
 * written against the instruction would then never see it. Injected text lands at either end, so both
 * ends must survive.
 *
 * A separate constant from `MAX_COMMAND_CHARS` deliberately: a command and a prompt are different
 * inputs with different evaluators, and retuning one must not silently retune the other.
 */
export const MAX_PROMPT_CHARS = 8192;
/**
 * WR-04: the per-value cap on what survives `TOOL_INPUT_ALLOWLIST`. `pattern` is model-produced and
 * free-form, and the server truncates it at 4096 anyway (`effectiveCommand.ts:20 PATTERN_MAX`), so
 * 2 KB costs no enforcement and bounds what a single value can carry off the machine.
 */
export const MAX_TOOL_INPUT_VALUE_BYTES = 2048;
/**
 * The only `metadata.tool_input` keys that leave the machine (WR-04 / T-09-03).
 *
 * `tool_input` has three consumers in `preToolUseHandler.ts`: `:914` (MCP input DLP — a pi tool call
 * never takes that path), `:1201` (RepoGate only) and `:1594` (`buildSyntheticPattern`, which reads
 * `pattern` for grep/find and nothing else). File paths arrive as `metadata.file_path`, not from here
 * (§C4). So `content` (write) and `edits` (edit) are read by nothing at all, and forwarding them was
 * undeclared egress of file contents.
 *
 * **Widening this list is an egress decision, not a convenience.** A test spells the set out
 * independently so an addition cannot be slipped in as a formatting change.
 */
export const TOOL_INPUT_ALLOWLIST = [
  "path",
  "pattern",
  "glob",
  "ignoreCase",
  "literal",
  "limit",
  "offset",
  "timeout",
] as const;

// --- User-facing strings, locked verbatim by 08-CONTEXT.md ------------------------------------
/** Note the trailing space: the API reason is appended directly after it. */
export const DENY_PREFIX = "Blocked by Unbound policy: ";
/** Used when a deny response carries no `reason` at all (nothing guarantees one, §B2). */
export const GENERIC_DENY_REASON = "Blocked by Unbound policy.";
export const DECLINED_REASON = "Declined by user (Unbound policy)";
/** Dialog title; pi renders a confirm as a Yes/No selector titled `title\nmessage` (§A5). */
export const CONFIRM_TITLE = "Unbound policy";
/** Appended after the API reason in the confirm body, so the dialog actually asks something. */
export const CONFIRM_QUESTION_SUFFIX = "\n\nRun this command?";
export const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
export const ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable — please retry";
export const NO_KEY_NOTICE = "Unbound: no API key found — extension inactive";
/**
 * WR-02, locked verbatim by 09-CONTEXT.md. Emitted once when the breaker opens — the developer is
 * entitled to know that the next minute of tool calls is unchecked.
 */
export const BREAKER_OPEN_NOTICE = "Unbound policy engine unreachable — allowing tool calls for 60 s";
/** The other edge: emitted once when a half-open probe succeeds. */
export const BREAKER_CLOSED_NOTICE = "Unbound policy engine reachable again — enforcement resumed";
/**
 * WR-01, locked verbatim by 09-CONTEXT.md. The only signal a developer gets that their key was
 * rejected — after it, the session is deliberately silent, so this one notice carries the whole
 * message.
 */
export const KEY_REJECTED_NOTICE = "Unbound: API key rejected — enforcement inactive";
/**
 * The fail-CLOSED half of WR-01. An org that opted out of fail-open does not get the latch above:
 * going quiet on a credential problem would hand anyone able to produce a 401/403 on this path — a
 * loopback proxy, corporate egress, a WAF — a session-long enforcement shutdown, for exactly the
 * customers who paid for the opposite. So the rejection blocks, and says why.
 *
 * It replaces `ENGINE_UNAVAILABLE_REASON` on that path only: "please retry" is the wrong advice when
 * retrying cannot work. The session stays active, so the fix is to correct the key, not to reload.
 */
export const KEY_REJECTED_BLOCK_REASON =
  "Unbound API key rejected — this organisation enforces fail-closed; contact your admin";
