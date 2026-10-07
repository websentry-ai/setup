// User-facing text that only makes sense for pi.
//
// Core's `constants.ts` holds the strings every agent shares (the deny prefix, the confirm title,
// the engine-unavailable reason). A string whose wording names pi or one of pi's own CLI modes lives
// here instead, so core never carries an agent's name.

/**
 * The block reason when a verdict needs a confirmation and there is nobody to ask. `-p` and `json`
 * are pi's non-interactive modes; locked verbatim by 08-CONTEXT.md.
 */
export const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";

// --- pi-mcp-adapter (MCP tool calls) ---------------------------------------------------------
//
// pi has no native MCP; MCP tools arrive through the `pi-mcp-adapter` extension. Enforcement rides
// the adapter's own approval broker (>= 2.21.0), which hands us the exact server, tool and arguments
// it is about to run. These are the adapter's own names, transcribed so nothing imports the adapter.

/**
 * The adapter's broker event (`types.ts MCP_TOOL_APPROVAL_REQUEST_EVENT`, README "Tool Approval").
 * Emitted on `pi.events` for EVERY resolved MCP call — proxy, direct, `mcpScript`, resource, iframe.
 */
export const MCP_TOOL_APPROVAL_REQUEST_EVENT = "pi-mcp-adapter:tool-approval-request";
/** The adapter's proxy tool: `mcp({tool, args, server?})`. Used only to correlate audit ids. */
export const MCP_PROXY_TOOL_NAME = "mcp";
/** Namespace wrappers are `mcp__<namespace>`. Used only to correlate audit ids. */
export const MCP_NAMESPACE_TOOL_PREFIX = "mcp__";
/**
 * Prefix of the `tool_use_id` minted for a brokered call that no in-flight `tool_call` matched (an
 * `mcpScript` call, a resource read, an iframe). Distinct from `toolu_…`/`ubash_…` so a row says so.
 */
export const MCP_BROKER_ID_PREFIX = "mcpb_";
/** In-flight non-native tool calls remembered for audit correlation. Oldest dropped past this. */
export const MAX_INFLIGHT_MCP_CALLS = 64;
/**
 * How long an in-flight non-native `tool_call` stays claimable by a broker request (5 min). An entry
 * whose `tool_result` never fires (a call blocked upstream) must not be claimed by an unrelated call
 * later — audit correlation only.
 */
export const MCP_INFLIGHT_MAX_AGE_MS = 300_000;
/** `PI_MCP_CONFIG_MODE=exclusive` makes the adapter read only its own config file. */
export const ENV_PI_MCP_CONFIG_MODE = "PI_MCP_CONFIG_MODE";
/** The adapter's own config file, under the agent dir and under `<cwd>/.pi/`. */
export const MCP_ADAPTER_CONFIG_FILE_NAME = "mcp-adapter.json";
/** The pi CLI flag the adapter registers to replace that file. Its presence omits the config. */
export const MCP_CONFIG_FLAG = "--mcp-config";
/**
 * The cap on one MCP config file (1 MiB; adapter configs are kilobytes). A file over it is "unknown",
 * which omits `mcp_server_config` rather than guessing.
 */
export const MAX_MCP_CONFIG_BYTES = 1_048_576;
