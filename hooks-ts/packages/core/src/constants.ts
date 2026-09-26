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
export const PRETOOL_PATH = "/v1/hooks/pretool";
export const ERRORS_PATH = "/v1/hooks/errors";

// --- Timeouts (RESEARCH §F5: an unbounded confirm hangs the whole tool batch) -----------------
export const PRETOOL_TIMEOUT_MS = 20_000;
export const ERRORS_TIMEOUT_MS = 10_000;
export const CONFIRM_TIMEOUT_MS = 120_000;
/** One bypass self-report per minute, per `unbound.py`'s convention (§B7). */
export const ERROR_REPORT_INTERVAL_MS = 60_000;
export const ERROR_CATEGORY_BYPASS = "bypassed_due_to_failure";
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
export const MAX_TOOL_INPUT_BYTES = 16_384;
export const MAX_COMMAND_CHARS = 8192;

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
