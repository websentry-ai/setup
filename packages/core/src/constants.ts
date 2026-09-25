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
export const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
export const ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable — please retry";
export const NO_KEY_NOTICE = "Unbound: no API key found — extension inactive";
