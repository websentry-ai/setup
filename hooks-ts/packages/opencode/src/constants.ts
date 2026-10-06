// opencode-only facts. Core's constants stay agent-neutral; anything that names opencode, its
// directories or its environment lives here.

/** The plugin id opencode registers this plugin under (`export default { id, server, setup }`). */
export const PLUGIN_ID = "unbound";
/** Key for `Symbol.for(...)`: the process-wide marker that detects a second loaded copy. */
export const SENTINEL_KEY = "unbound.opencode";
/** `client_entrypoint` until the host version is learned at runtime. */
export const UNKNOWN_ENTRYPOINT = "opencode/unknown";
/** `client_entrypoint` prefix: `opencode/<version>`. */
export const ENTRYPOINT_PREFIX = "opencode/";

/** opencode's own config-dir override; tilde-expanded, absolute only. */
export const ENV_OPENCODE_CONFIG_DIR = "OPENCODE_CONFIG_DIR";
/** XDG config base (xdg-basedir; `~/.config` on macOS too). Absolute only. */
export const ENV_XDG_CONFIG_HOME = "XDG_CONFIG_HOME";
/** XDG data base (xdg-basedir; `~/.local/share` on macOS too). Absolute only. */
export const ENV_XDG_DATA_HOME = "XDG_DATA_HOME";
/** JSON that replaces `auth.json` wholesale when set (`oc:opencode/src/auth/index.ts:59-61`). */
export const ENV_OPENCODE_AUTH_CONTENT = "OPENCODE_AUTH_CONTENT";
/** The directory name under the XDG config and data bases. */
export const OPENCODE_DIR_NAME = "opencode";
/** opencode's credential store, in its data dir. Read, never written. */
export const AUTH_FILE_NAME = "auth.json";
/** `~/.config`, the XDG config default. */
export const XDG_CONFIG_DEFAULT_SEGMENTS = [".config"] as const;
/** `~/.local/share`, the XDG data default. */
export const XDG_DATA_DEFAULT_SEGMENTS = [".local", "share"] as const;

// --- signal categories (core's signal reporter; observations, never enforcement outcomes) -------
/** A second copy of the plugin loaded into the same process. */
export const SIGNAL_DUPLICATE_LOAD = "duplicate_load";
/** The double-load sentinel slot held something other than a copy of this build; still enforcing. */
export const SIGNAL_SENTINEL_TAMPERED = "sentinel_tampered";
/** Plugin init could not complete fully and runs degraded. */
export const SIGNAL_INIT_DEGRADED = "init_degraded";
/** A tool looked like MCP but could not be attributed to a configured server. */
export const SIGNAL_MCP_ATTRIBUTION_MISS = "mcp_attribution_miss";
/** More than one configured MCP server could have produced a tool id; every candidate was checked. */
export const SIGNAL_MCP_ATTRIBUTION_AMBIGUOUS = "mcp_attribution_ambiguous";
/** Tool arguments changed between the check and execution. */
export const SIGNAL_ARGS_CHANGED = "args_changed_after_check";
/** A user shell command ran without a check. */
export const SIGNAL_USER_SHELL_UNCHECKED = "user_shell_unchecked";
/** The v2 entry was loaded on a host whose v2 hook family is not active (or the reverse). */
export const SIGNAL_API_FAMILY_INACTIVE = "api_family_inactive";
/** An apply_patch named more distinct files than `MAX_PATCH_TARGETS` (and was blocked). */
export const SIGNAL_PATCH_TARGETS_CAPPED = "patch_targets_capped";

// --- notices ------------------------------------------------------------------------------------
/** Shown once per directory when resolving the key / gateway / checker raised (13-REVIEW WR-03). */
export const INIT_ERROR_NOTICE =
  "Unbound: the policy plugin could not start (configuration error) — tool calls are not checked; it retries automatically";

// --- limits -------------------------------------------------------------------------------------
/** The most distinct files one apply_patch is checked for; a patch naming more is blocked. */
export const MAX_PATCH_TARGETS = 1024;
/** How many per-file apply_patch checks run at once. */
export const PATCH_CONCURRENCY = 8;
/** Upper bound on waiting for a toast before blocking. */
export const TOAST_TIMEOUT_MS = 1000;
