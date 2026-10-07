/**
 * GENERATED FILE - DO NOT EDIT.
 * Built from unbound-hooks-ts (packages/core + packages/opencode) by scripts/build.mjs.
 *
 * Fail-open contract (opencode v1 `server` entry): when the Unbound API cannot be reached, times
 * out, answers non-2xx or returns unparseable JSON, the tool call or prompt is ALLOWED. An error
 * escaping `tool.execute.before` or `chat.message` would block, so every handler is total, and
 * the only deliberate blocks are a policy deny, an approval-required verdict (opencode v1 has no
 * native ask), or an org whose last successful response asked for block-on-failure.
 *
 * The v2 `setup` entry is present but INACTIVE: it enforces nothing and, on a v2 host only,
 * reports itself inactive.
 *
 * Tested against opencode-ai 1.18.x (Bun-compiled CLI); also importable on Node >= 22.19.0.
 */

// packages/opencode/src/constants.ts
var PLUGIN_ID = "unbound";
var SENTINEL_KEY = "unbound.opencode";
var UNKNOWN_ENTRYPOINT = "opencode/unknown";
var ENTRYPOINT_PREFIX = "opencode/";
var ENV_OPENCODE_CONFIG_DIR = "OPENCODE_CONFIG_DIR";
var ENV_XDG_CONFIG_HOME = "XDG_CONFIG_HOME";
var ENV_XDG_DATA_HOME = "XDG_DATA_HOME";
var ENV_OPENCODE_AUTH_CONTENT = "OPENCODE_AUTH_CONTENT";
var OPENCODE_DIR_NAME = "opencode";
var AUTH_FILE_NAME = "auth.json";
var XDG_CONFIG_DEFAULT_SEGMENTS = [".config"];
var XDG_DATA_DEFAULT_SEGMENTS = [".local", "share"];
var SIGNAL_DUPLICATE_LOAD = "duplicate_load";
var SIGNAL_SENTINEL_TAMPERED = "sentinel_tampered";
var SIGNAL_INIT_DEGRADED = "init_degraded";
var SIGNAL_MCP_ATTRIBUTION_MISS = "mcp_attribution_miss";
var SIGNAL_MCP_ATTRIBUTION_AMBIGUOUS = "mcp_attribution_ambiguous";
var SIGNAL_ARGS_CHANGED = "args_changed_after_check";
var SIGNAL_USER_SHELL_UNCHECKED = "user_shell_unchecked";
var SIGNAL_PATCH_TARGETS_CAPPED = "patch_targets_capped";
var SIGNAL_V2_STATUS = "v2_status";
var SIGNAL_V2_NOT_ENFORCING = "v2_not_enforcing";
var SIGNAL_V2_PROMPT_WARN_ONLY = "v2_prompt_warn_only";
var V2_CAPABILITIES = Object.freeze({
  /** HV2-02 GO lever=both (permission.evaluate deny + message; an execute.before raise for MCP). */
  tools: "enforce",
  /** HV2-03 NATIVE (`effect = "ask"` → opencode's own pending permission; reject prevents execution). */
  ask: "native",
  /** HV2-04 GO (MCP ids `<server>_<tool>` reach execute.before and evaluate). */
  mcp: "enforce",
  /** HV2-05 BLOCK lever=session.prompt-mutate. */
  prompt: "block",
  /** HV2-06 GO (session.created / execution.succeeded / text.ended / step.ended events). */
  recording: "full",
  /** HV2-07 PROVIDER-LEVEL source=session.model.request.model.providerID. */
  identity: "provider",
  /** V2-10: user shell checked in shell.create.before, raised on a would-block verdict. */
  userShell: "enforce"
});
var INIT_ERROR_NOTICE = "Unbound: the policy plugin could not start (configuration error) \u2014 tool calls are not checked; it retries automatically";
var MAX_PATCH_TARGETS = 1024;
var PATCH_CONCURRENCY = 8;
var TOAST_TIMEOUT_MS = 1e3;

// packages/opencode/src/plugin.ts
import { homedir } from "node:os";

// packages/core/src/constants.ts
var ENV_API_KEY_GENERIC = "UNBOUND_API_KEY";
var ENV_GATEWAY_URL = "UNBOUND_GATEWAY_URL";
var DEFAULT_GATEWAY_URL = "https://api.getunbound.ai";
var CONFIG_DIR_NAME = ".unbound";
var CONFIG_FILE_NAME = "config.json";
var CACHE_DIR_NAME = ".unbound";
var CACHE_FILE_NAME = "policy_cache.json";
var KEY_FINGERPRINT_PREFIX = "sha256:";
var EVENT_NAME_TOOL_USE = "tool_use";
var EVENT_NAME_SESSION_START = "session_start";
var EVENT_NAME_USER_PROMPT = "user_prompt";
var USER_BASH_ID_PREFIX = "ubash_";
var PRETOOL_PATH = "/v1/hooks/pretool";
var ERRORS_PATH = "/v1/hooks/errors";
var TURNLOG_MODEL = "auto";
var TURNLOG_TOOL_USE_TYPE = "PostToolUse";
var PRETOOL_TIMEOUT_MS = 2e4;
var EVALUATE_DEADLINE_SLACK_MS = 2e3;
var EVALUATE_DEADLINE_ERROR_CLASS = "EvaluateDeadline";
var ERRORS_TIMEOUT_MS = 1e4;
var TURNLOG_TIMEOUT_MS = 1e4;
var ERROR_REPORT_INTERVAL_MS = 6e4;
var ERROR_CATEGORY_BYPASS = "bypassed_due_to_failure";
var ERROR_CATEGORY_BLOCKED = "blocked_due_to_failure";
var ERROR_CATEGORY_TURNLOG = "turn_log_failed";
var KEY_REJECTION_THRESHOLD = 2;
var BREAKER_FAILURE_THRESHOLD = 3;
var BREAKER_OPEN_MS = 6e4;
var CACHE_TTL_MS = 3e5;
var MAX_TRACKED_SESSIONS = 256;
var MAX_TRACKED_INSTANCES = 64;
var MAX_TRACKED_GATEWAYS = 16;
var MAX_TRACKED_SCOPES = 16;
var DEFAULT_KEYED_STATE_MAX = MAX_TRACKED_SESSIONS;
var MAX_REASON_CHARS = 2e3;
var MAX_CACHE_BYTES = 65536;
var MAX_TOOLS_TO_CHECK = 256;
var MAX_TOOL_NAME_CHARS = 64;
var MAX_CONFIG_BYTES = 262144;
var MAX_HASH_BYTES = 4194304;
var MAX_TURN_RESULTS = 500;
var MAX_TURN_OUTPUT_CHARS = 131072;
var MAX_TURN_TOOL_CALLS = 500;
var MAX_TOOL_INPUT_BYTES = 16384;
var MAX_COMMAND_CHARS = 8192;
var MAX_PROMPT_CHARS = 8192;
var MAX_ASSISTANT_CHARS = 16384;
var MAX_TOOL_INPUT_VALUE_BYTES = 2048;
var MAX_MCP_NAME_CHARS = 256;
var TOOL_INPUT_ALLOWLIST = [
  "path",
  "pattern",
  "glob",
  "ignoreCase",
  "literal",
  "limit",
  "offset",
  "timeout"
];
var DENY_PREFIX = "Blocked by Unbound policy: ";
var GENERIC_DENY_REASON = "Blocked by Unbound policy.";
var ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable \u2014 please retry";
var NO_KEY_NOTICE = "Unbound: no API key found \u2014 extension inactive";
var BREAKER_OPEN_NOTICE = "Unbound policy engine unreachable \u2014 allowing tool calls for 60 s";
var BREAKER_CLOSED_NOTICE = "Unbound policy engine reachable again \u2014 enforcement resumed";
var KEY_REJECTED_NOTICE = "Unbound: API key rejected \u2014 enforcement inactive";
var KEY_REJECTED_BLOCK_REASON = "Unbound API key rejected \u2014 this organisation enforces fail-closed; contact your admin";
var MAX_AUTH_FILE_BYTES = 65536;
var ANTHROPIC_PROVIDER_ID = "anthropic";
var ANTHROPIC_PROFILE_URL = "https://api.anthropic.com/api/oauth/profile";
var ANTHROPIC_OAUTH_BETA_HEADER = "anthropic-beta";
var ANTHROPIC_OAUTH_BETA_VALUE = "oauth-2025-04-20";
var MAX_PROFILE_BYTES = 65536;
var MAX_IDENTITY_FIELD_CHARS = 320;
var ACCOUNT_IDENTITY_TIMEOUT_MS = 1e4;
var AUTH_MODE_SUBSCRIPTION = "subscription";
var AUTH_MODE_API_KEY = "api_key";
var MAX_SERIAL_PROBE_BYTES = 1048576;
var LINUX_MACHINE_ID_PATHS = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
var PLACEHOLDER_SERIALS = [
  "",
  "0",
  "00000000",
  "000000000",
  "0000000000",
  "none",
  "na",
  "n/a",
  "unknown",
  "default",
  "default string",
  "to be filled by o.e.m.",
  "to be filled by oem",
  "system serial number",
  "serial number",
  "not applicable",
  "not specified",
  "not available",
  "oem",
  "o.e.m.",
  "invalid",
  "123456789",
  "xxxxxxxx"
];
var MAX_MCP_ARGS_BYTES = 524288;
var MAX_PRETOOL_BODY_BYTES = 921600;

// packages/core/src/breaker.ts
function createBreaker(opts = {}) {
  const now = opts.now ?? Date.now;
  const threshold = typeof opts.threshold === "number" && opts.threshold > 0 ? opts.threshold : BREAKER_FAILURE_THRESHOLD;
  const openMs = typeof opts.openMs === "number" && opts.openMs > 0 ? opts.openMs : BREAKER_OPEN_MS;
  let consecutiveFailures = 0;
  let openedAtMs;
  let probeStartedAtMs;
  function phase() {
    if (openedAtMs === void 0) return "closed";
    return now() - openedAtMs > openMs ? "half-open" : "open";
  }
  return {
    shouldSkip() {
      const current = phase();
      if (current === "closed") return false;
      if (current === "open") return true;
      if (probeStartedAtMs !== void 0 && now() - probeStartedAtMs <= openMs) return true;
      probeStartedAtMs = now();
      return false;
    },
    recordFailure() {
      probeStartedAtMs = void 0;
      consecutiveFailures += 1;
      if (consecutiveFailures < threshold) return void 0;
      const wasOpen = openedAtMs !== void 0;
      openedAtMs = now();
      return wasOpen ? void 0 : "opened";
    },
    recordSuccess() {
      const wasOpen = openedAtMs !== void 0;
      consecutiveFailures = 0;
      openedAtMs = void 0;
      probeStartedAtMs = void 0;
      return wasOpen ? "closed" : void 0;
    },
    state: phase
  };
}

// packages/core/src/config.ts
import { isAbsolute, join } from "node:path";

// packages/core/src/safeRead.ts
import { lstatSync, readFileSync } from "node:fs";
function readSmallRegularFile(path, maxBytes) {
  try {
    if (typeof path !== "string" || path === "") return void 0;
    const stats = lstatSync(path);
    if (!stats.isFile()) return void 0;
    const size = stats.size;
    if (typeof size !== "number" || !Number.isFinite(size) || size > maxBytes) return void 0;
    return readFileSync(path, "utf8");
  } catch {
    return void 0;
  }
}

// packages/core/src/config.ts
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function readUnboundConfig(homeDir) {
  if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute(homeDir)) return {};
  const raw = readSmallRegularFile(join(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), MAX_CONFIG_BYTES);
  if (raw === void 0) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed;
  } catch {
    return {};
  }
}
function usableString(candidate) {
  if (typeof candidate !== "string") return void 0;
  const trimmed = candidate.trim();
  return trimmed.length > 0 ? trimmed : void 0;
}
function resolveApiKey(env, homeDir, profile) {
  const fromEnv = usableString(env[profile.envApiKey]) ?? usableString(env[ENV_API_KEY_GENERIC]);
  if (fromEnv !== void 0) return fromEnv;
  return usableString(readUnboundConfig(homeDir).api_key);
}
function normalizeGatewayUrl(raw) {
  const candidate = usableString(raw);
  if (candidate === void 0) return void 0;
  try {
    const url = new URL(candidate);
    const isLoopbackHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !isLoopbackHttp) return void 0;
    if (url.username !== "" || url.password !== "") return void 0;
    const path = url.pathname.replace(/\/+$/, "");
    return path === "" ? url.origin : url.origin + path;
  } catch {
    return void 0;
  }
}
function resolveGatewayUrl(env, homeDir) {
  const fromEnv = normalizeGatewayUrl(env[ENV_GATEWAY_URL]);
  if (fromEnv !== void 0) return fromEnv;
  const fromFile = normalizeGatewayUrl(readUnboundConfig(homeDir).gateway_url);
  return fromFile ?? DEFAULT_GATEWAY_URL;
}
function redactSecrets(text, apiKey) {
  let out = text.replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]");
  if (apiKey !== void 0 && apiKey.length >= 8) {
    out = out.split(apiKey).join("[REDACTED]");
  }
  return out;
}

// packages/core/src/keyedState.ts
function clampMax(max) {
  if (typeof max !== "number" || !Number.isFinite(max) || max < 1) return DEFAULT_KEYED_STATE_MAX;
  return Math.floor(max);
}
function createKeyedState(opts) {
  const entries = /* @__PURE__ */ new Map();
  const max = clampMax(opts?.max);
  let evicting = 0;
  function keyOf(raw) {
    try {
      const normalize = opts?.normalizeKey;
      const key = typeof normalize === "function" ? normalize(raw) : raw;
      return typeof key === "string" && key !== "" ? key : void 0;
    } catch {
      return void 0;
    }
  }
  function fallbackValue() {
    try {
      return opts.fallback();
    } catch {
      return void 0;
    }
  }
  function report(key, value) {
    evicting += 1;
    try {
      opts?.onEvict?.(key, value);
    } catch {
    } finally {
      evicting -= 1;
    }
  }
  function enforceBound() {
    while (entries.size > max) {
      const oldest = entries.keys().next();
      if (oldest.done === true) return;
      const value = entries.get(oldest.value);
      entries.delete(oldest.value);
      report(oldest.value, value);
    }
  }
  return {
    get(raw) {
      try {
        const key = keyOf(raw);
        if (key === void 0) return fallbackValue();
        if (entries.has(key)) {
          const existing = entries.get(key);
          entries.delete(key);
          entries.set(key, existing);
          return existing;
        }
        if (evicting > 0) return fallbackValue();
        let created;
        try {
          created = opts.create(key);
        } catch {
          return fallbackValue();
        }
        entries.set(key, created);
        enforceBound();
        return created;
      } catch {
        return fallbackValue();
      }
    },
    peek(raw) {
      try {
        const key = keyOf(raw);
        return key === void 0 ? void 0 : entries.get(key);
      } catch {
        return void 0;
      }
    },
    release(raw) {
      try {
        const key = keyOf(raw);
        if (key === void 0 || !entries.has(key)) return;
        const value = entries.get(key);
        entries.delete(key);
        report(key, value);
      } catch {
      }
    },
    clear() {
      try {
        const leaving = [...entries];
        entries.clear();
        for (const [key, value] of leaving) report(key, value);
      } catch {
      }
    },
    size() {
      return entries.size;
    },
    keys() {
      try {
        return [...entries.keys()];
      } catch {
        return [];
      }
    }
  };
}

// packages/core/src/breakerRegistry.ts
function createBreakerRegistry(opts = {}) {
  const fresh = () => createBreaker({ now: opts?.now, threshold: opts?.threshold, openMs: opts?.openMs });
  const breakers = createKeyedState({
    max: opts?.max ?? MAX_TRACKED_GATEWAYS,
    normalizeKey: normalizeGatewayUrl,
    create: fresh,
    fallback: fresh
  });
  return {
    forUrl: (baseUrl) => breakers.get(baseUrl),
    size: () => breakers.size(),
    clear: () => breakers.clear()
  };
}

// packages/core/src/cache.ts
import { chmodSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute as isAbsolute2, join as join2 } from "node:path";

// packages/core/src/policyState.ts
function parseFailureAction(raw) {
  return raw === "allow" || raw === "block" ? raw : void 0;
}
function parseToolsToCheck(raw) {
  if (!Array.isArray(raw)) return void 0;
  if (raw.length > MAX_TOOLS_TO_CHECK) return void 0;
  const usable = raw.filter(
    (entry) => typeof entry === "string" && entry.length <= MAX_TOOL_NAME_CHARS
  );
  if (usable.length !== raw.length) return void 0;
  return usable;
}
function parseTimestamp(raw) {
  return typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? raw : void 0;
}
function createPolicyState() {
  let failureAction;
  let toolsToCheck;
  let toolsSyncedAt;
  let fetchedAt;
  let toolsConfirmed = false;
  return {
    recordSuccess(body, nowMs = Date.now()) {
      let learned = false;
      const nextTools = parseToolsToCheck(body?.tools_to_check);
      if (nextTools !== void 0) {
        toolsToCheck = nextTools;
        toolsSyncedAt = nowMs;
        toolsConfirmed = true;
        learned = true;
      }
      const nextAction = parseFailureAction(body?.policy_check_failure_action);
      if (nextAction !== void 0) {
        failureAction = nextAction;
        learned = true;
      }
      if (learned) fetchedAt = nowMs;
    },
    getFailureAction: () => failureAction,
    // Copy out: a caller that mutates the returned array must not widen the skip set.
    getToolsToCheck: () => toolsToCheck === void 0 ? void 0 : [...toolsToCheck],
    getToolsSyncedAt: () => toolsSyncedAt,
    getToolsConfirmed: () => toolsConfirmed,
    getFetchedAt: () => fetchedAt,
    /** Only what was actually learned. An absent key is the honest encoding of "never learned". */
    snapshot() {
      const out = {};
      if (fetchedAt !== void 0) out.fetched_at = fetchedAt;
      if (toolsSyncedAt !== void 0) out.tools_synced_at = toolsSyncedAt;
      if (toolsToCheck !== void 0) out.tools_to_check = [...toolsToCheck];
      if (failureAction !== void 0) out.policy_check_failure_action = failureAction;
      return out;
    },
    /**
     * Load a disk snapshot, **without downgrading anything learned over the network**. In-memory is
     * authoritative for the session (09-CONTEXT), which is also what caps T-09-01/T-09-02: a planted
     * cache can only ever influence a value this instance has not yet been told by the server.
     *
     * **`toolsConfirmed` is deliberately not set here** (WR-02). "A value the server has not told us
     * yet" was doing more work than it looked: the cold window is every session start, and the old
     * `pullPolicies = !areToolsFresh(hydrated stamp)` then declined to ask the server during exactly
     * that window — so a planted `tools_to_check: []` with a fresh stamp suppressed all six native
     * file-tool checks for a full TTL, renewably, with nothing able to correct it. Leaving this bit
     * false is what makes `decide.ts` confirm a hydrated list once per process.
     *
     * Every field is re-validated. This object came off a file, so its types are claims.
     */
    hydrate(snapshot) {
      if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) return;
      if (toolsSyncedAt === void 0) {
        const tools = parseToolsToCheck(snapshot.tools_to_check);
        const syncedAt = parseTimestamp(snapshot.tools_synced_at);
        if (tools !== void 0 && syncedAt !== void 0) {
          toolsToCheck = tools;
          toolsSyncedAt = syncedAt;
        }
      }
      if (fetchedAt === void 0) {
        const action = parseFailureAction(snapshot.policy_check_failure_action);
        if (action !== void 0) failureAction = action;
        const fetched = parseTimestamp(snapshot.fetched_at);
        if (fetched !== void 0) fetchedAt = fetched;
      }
    }
  };
}
var policyState = createPolicyState();

// packages/core/src/payload.ts
var NO_FILE_TOOLS = /* @__PURE__ */ new Set();
var nativeFileToolsMemo = /* @__PURE__ */ new WeakMap();
function nativeFileTools(fileTools) {
  try {
    if (fileTools === null || typeof fileTools !== "object") return NO_FILE_TOOLS;
    const known = nativeFileToolsMemo.get(fileTools);
    if (known !== void 0) return known;
    const union = /* @__PURE__ */ new Set();
    for (const name of fileTools.defaulting) if (typeof name === "string") union.add(name);
    for (const name of fileTools.required) if (typeof name === "string") union.add(name);
    nativeFileToolsMemo.set(fileTools, union);
    return union;
  } catch {
    return NO_FILE_TOOLS;
  }
}
function resolveFilePath(toolName, toolInput, cwd, fileTools) {
  let isDefaulting;
  try {
    isDefaulting = fileTools.defaulting.has(toolName) === true;
    if (!isDefaulting && fileTools.required.has(toolName) !== true) return void 0;
  } catch {
    return void 0;
  }
  let path;
  try {
    path = fileTools.pathOf(toolName, toolInput);
  } catch {
    path = void 0;
  }
  if (typeof path === "string" && path.length > 0) return path;
  return isDefaulting ? cwd : void 0;
}
var ALLOWED_TOOL_INPUT_KEYS = new Set(TOOL_INPUT_ALLOWLIST);
function allowedKeysFor(extraKeys) {
  try {
    if (!Array.isArray(extraKeys) || extraKeys.length === 0) return ALLOWED_TOOL_INPUT_KEYS;
    const allowed = new Set(ALLOWED_TOOL_INPUT_KEYS);
    for (const key of extraKeys) if (typeof key === "string" && key !== "") allowed.add(key);
    return allowed;
  } catch {
    return ALLOWED_TOOL_INPUT_KEYS;
  }
}
function profileExtraToolInputKeys(profile) {
  try {
    if (profile === null || typeof profile !== "object") return void 0;
    const keys = profile.extraToolInputKeys;
    return Array.isArray(keys) ? keys : void 0;
  } catch {
    return void 0;
  }
}
function validMcpName(value) {
  if (typeof value !== "string" || value.trim() === "" || value.length > MAX_MCP_NAME_CHARS) return void 0;
  return value;
}
function normaliseMcp(raw) {
  try {
    if (raw === null || typeof raw !== "object") return void 0;
    const server = validMcpName(raw.server);
    if (server === void 0) return void 0;
    const tool = validMcpName(raw.tool);
    return tool === void 0 ? { server } : { server, tool };
  } catch {
    return void 0;
  }
}
function sliceToBytes(value, maxBytes) {
  if (Buffer.byteLength(value) <= maxBytes) return value;
  let out = "";
  let usedBytes = 0;
  for (const char of value) {
    const size = Buffer.byteLength(char);
    if (usedBytes + size > maxBytes) break;
    out += char;
    usedBytes += size;
  }
  return out;
}
function sanitizeToolInput(toolInput, extraKeys) {
  const out = {};
  if (toolInput === null || typeof toolInput !== "object" || Array.isArray(toolInput)) return out;
  const allowed = allowedKeysFor(extraKeys);
  let dropped = false;
  let truncated = false;
  for (const [key, value] of Object.entries(toolInput)) {
    if (!allowed.has(key)) {
      dropped = true;
      continue;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
      continue;
    }
    if (typeof value !== "string") {
      dropped = true;
      continue;
    }
    const sliced = sliceToBytes(value, MAX_TOOL_INPUT_VALUE_BYTES);
    if (sliced.length !== value.length) truncated = true;
    out[key] = sliced;
  }
  if (truncated) out._truncated = true;
  if (dropped) out._dropped = true;
  return out;
}
function capToolInput(toolInput, maxBytes = MAX_TOOL_INPUT_BYTES) {
  let serialised;
  try {
    serialised = JSON.stringify(toolInput) ?? "";
  } catch {
    return { _unserializable: true };
  }
  const originalBytes = Buffer.byteLength(serialised);
  if (originalBytes <= maxBytes) return toolInput;
  const capped = { _truncated: true, _original_bytes: originalBytes };
  let usedBytes = Buffer.byteLength(JSON.stringify(capped));
  for (const [key, value] of Object.entries(toolInput)) {
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") continue;
    const entryBytes = Buffer.byteLength(JSON.stringify(key)) + Buffer.byteLength(JSON.stringify(value)) + 2;
    if (usedBytes + entryBytes > maxBytes) continue;
    capped[key] = value;
    usedBytes += entryBytes;
  }
  return capped;
}
var COMMAND_TRUNCATION_MARKER = "\n#...unbound: omitted...\n";
function capCommand(command, maxChars = MAX_COMMAND_CHARS) {
  if (command.length <= maxChars) return { command, truncated: false };
  const budget = maxChars - COMMAND_TRUNCATION_MARKER.length;
  if (budget <= 1) return { command: command.slice(0, maxChars), truncated: true };
  const headChars = Math.ceil(budget / 2);
  const tailChars = budget - headChars;
  return {
    command: command.slice(0, headChars) + COMMAND_TRUNCATION_MARKER + command.slice(-tailChars),
    truncated: true
  };
}
function auditToolInput(toolInput, command, extraKeys) {
  const isObject = toolInput !== null && typeof toolInput === "object" && !Array.isArray(toolInput);
  const source = isObject ? { ...toolInput } : {};
  delete source.command;
  const out = sanitizeToolInput(source, extraKeys);
  if (typeof command === "string" && command !== "") out.command = capCommand(command).command;
  return capToolInput(out);
}
var IDENTITY_FIELDS = [
  "user_email",
  "org_id",
  "plan",
  "auth_mode",
  "email_domain",
  "device_serial"
];
function sanitizeAccountIdentity(identity) {
  try {
    if (identity === null || typeof identity !== "object" || Array.isArray(identity)) return void 0;
    const source = identity;
    const out = {};
    for (const field of IDENTITY_FIELDS) {
      const value = source[field];
      if (typeof value === "string" && value.trim() !== "") out[field] = value;
    }
    return Object.keys(out).length > 0 ? out : void 0;
  } catch {
    return void 0;
  }
}
function withAccountIdentity(body, identity) {
  const clean = sanitizeAccountIdentity(identity);
  if (clean !== void 0) body.account_identity = clean;
  return body;
}
var MCP_ARGS_TRUNCATION_MARKER = "\n...unbound: arguments truncated...\n";
var MAX_STRUCTURED_KEYS = 512;
var MIN_KEPT_VALUE_BYTES = 256;
var MAX_TRUNCATED_KEYS_REPORTED = 32;
var MAX_TRUNCATED_KEY_CHARS = 128;
function jsonBytes(value) {
  const text = JSON.stringify(value);
  return typeof text === "string" ? Buffer.byteLength(text) : 0;
}
function headTailFitting(text, targetBytes) {
  const markerBytes = Buffer.byteLength(MCP_ARGS_TRUNCATION_MARKER) + 8;
  let keep = Math.max(2, targetBytes - markerBytes);
  let candidate = MCP_ARGS_TRUNCATION_MARKER;
  for (let attempt2 = 0; attempt2 < 8; attempt2 += 1) {
    const half = Math.max(1, Math.floor(keep / 2));
    const head = Buffer.from(text.slice(0, half), "utf8").subarray(0, half).toString("utf8");
    const tailSource = Buffer.from(text.slice(-half), "utf8");
    const tail = tailSource.subarray(Math.max(0, tailSource.length - half)).toString("utf8");
    candidate = head + MCP_ARGS_TRUNCATION_MARKER + tail;
    const measured = jsonBytes(candidate);
    if (measured <= targetBytes) return candidate;
    keep = Math.floor(keep * targetBytes / measured) - 1;
    if (keep < 2) break;
  }
  return MCP_ARGS_TRUNCATION_MARKER;
}
function singleStringForm(serialised, maxBytes) {
  const half = Math.max(1, Math.floor((maxBytes - Buffer.byteLength(MCP_ARGS_TRUNCATION_MARKER)) / 2));
  const bytes = Buffer.from(serialised, "utf8");
  const head = bytes.subarray(0, half).toString("utf8");
  const tail = bytes.subarray(bytes.length - half).toString("utf8");
  return { _truncated_json: head + MCP_ARGS_TRUNCATION_MARKER + tail };
}
function mcpArgsForWire(args, maxBytes = MAX_MCP_ARGS_BYTES) {
  try {
    if (args === null || typeof args !== "object" || Array.isArray(args)) return { toolInput: {}, truncated: false };
    const serialised = JSON.stringify(args);
    if (typeof serialised !== "string") return { toolInput: { _unserializable: true }, truncated: true };
    const originalBytes = Buffer.byteLength(serialised);
    if (originalBytes <= maxBytes) return { toolInput: args, truncated: false };
    const keys = Object.keys(args);
    if (keys.length <= MAX_STRUCTURED_KEYS) {
      const entries = [];
      for (const key of keys) {
        const value = args[key];
        const text = JSON.stringify(value);
        if (typeof text !== "string") continue;
        entries.push({ key, value, size: Buffer.byteLength(text), overhead: jsonBytes(key) + 2, cut: false });
      }
      const totalOf = () => 2 + entries.reduce((sum, e) => sum + e.size + e.overhead, 0) - 1;
      let fits = false;
      for (let round = 0; round < entries.length * 4 + 16; round += 1) {
        const total = totalOf();
        if (total <= maxBytes) {
          fits = true;
          break;
        }
        let largest;
        for (const entry of entries) {
          if (entry.size > MIN_KEPT_VALUE_BYTES && (largest === void 0 || entry.size > largest.size)) largest = entry;
        }
        if (largest === void 0) break;
        const target = Math.max(MIN_KEPT_VALUE_BYTES, largest.size - (total - maxBytes));
        const source = typeof largest.value === "string" ? largest.value : JSON.stringify(largest.value) ?? "";
        largest.value = headTailFitting(source, target);
        largest.size = jsonBytes(largest.value);
        largest.cut = true;
      }
      if (fits) {
        const toolInput = {};
        for (const entry of entries) defineData(toolInput, entry.key, entry.value);
        const truncatedKeys = entries.filter((entry) => entry.cut).slice(0, MAX_TRUNCATED_KEYS_REPORTED).map((entry) => entry.key.slice(0, MAX_TRUNCATED_KEY_CHARS));
        return { toolInput, truncated: true, originalBytes, truncatedKeys };
      }
    }
    return { toolInput: singleStringForm(serialised, maxBytes), truncated: true, originalBytes };
  } catch {
    return { toolInput: { _unserializable: true }, truncated: true };
  }
}
function defineData(target, key, value) {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}
function brokeredMcpCall(raw) {
  try {
    if (raw === null || typeof raw !== "object") return void 0;
    const args = raw.args;
    return args !== null && typeof args === "object" ? raw : void 0;
  } catch {
    return void 0;
  }
}
function buildPretoolPayload(input, profile) {
  const brokered = brokeredMcpCall(input.mcp);
  const metadata = { cwd: input.cwd };
  if (brokered !== void 0) {
    metadata.mcp_server = brokered.server;
    metadata.mcp_tool = brokered.tool;
    applyWireArgs(metadata, mcpArgsForWire(brokered.args));
    if (brokered.serverConfig !== void 0) metadata.mcp_server_config = brokered.serverConfig;
    if (typeof brokered.origin === "string" && brokered.origin !== "") metadata.mcp_origin = brokered.origin;
  } else {
    metadata.tool_input = capToolInput(sanitizeToolInput(input.toolInput, profileExtraToolInputKeys(profile)));
    const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd, profile.fileTools);
    if (filePath !== void 0) metadata.file_path = filePath;
  }
  const capped = capCommand(brokered === void 0 ? input.command : "");
  if (capped.truncated) {
    metadata.command_truncated = true;
    metadata.command_original_chars = input.command.length;
  }
  const mcp = brokered === void 0 ? normaliseMcp(input.mcp) : void 0;
  if (mcp !== void 0) {
    metadata.mcp_server = mcp.server;
    if (mcp.tool !== void 0) metadata.mcp_tool = mcp.tool;
  }
  if (input.patchOperation === "delete") metadata.patch_operation = "delete";
  const preToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears. A resolved MCP call is
    // named the way the gateway and the backend parse MCP names, `mcp__<server>__<tool>`.
    tool_name: brokered === void 0 ? input.toolName : `mcp__${brokered.server}__${brokered.tool}`,
    command: capped.command,
    metadata
  };
  if (typeof input.toolUseId === "string" && input.toolUseId.length > 0) {
    preToolUseData.tool_use_id = input.toolUseId;
  }
  const body = {
    conversation_id: input.sessionId,
    // `model` is required on the wire and `ctx.model` may be undefined (§A4); `'auto'` is the same
    // fallback the Python hook uses.
    model: input.model !== void 0 && input.model.length > 0 ? input.model : "auto",
    event_name: EVENT_NAME_TOOL_USE,
    pre_tool_use_data: preToolUseData,
    messages: [{ role: "user", content: input.lastUserPrompt ?? "" }],
    unbound_app_label: profile.appLabel,
    client_entrypoint: input.clientEntrypoint
  };
  if (input.pullPolicies === true) body.pull_policies = true;
  const finished = withAccountIdentity(body, input.accountIdentity);
  if (brokered !== void 0) fitMcpBody(finished, brokered.args);
  return finished;
}
function applyWireArgs(metadata, wire) {
  metadata.tool_input = wire.toolInput;
  delete metadata.tool_input_truncated;
  delete metadata.tool_input_original_bytes;
  delete metadata.tool_input_truncated_keys;
  if (!wire.truncated) return;
  metadata.tool_input_truncated = true;
  if (wire.originalBytes !== void 0) metadata.tool_input_original_bytes = wire.originalBytes;
  if (wire.truncatedKeys !== void 0 && wire.truncatedKeys.length > 0) {
    metadata.tool_input_truncated_keys = wire.truncatedKeys;
  }
}
function serialisedBytes(value) {
  try {
    const text = JSON.stringify(value);
    return typeof text === "string" ? Buffer.byteLength(text) : Number.POSITIVE_INFINITY;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}
function fitMcpBody(body, args) {
  try {
    const metadata = body.pre_tool_use_data.metadata;
    let budget = MAX_MCP_ARGS_BYTES;
    while (serialisedBytes(body) >= MAX_PRETOOL_BODY_BYTES) {
      budget = Math.floor(budget / 2);
      if (budget < 1024) {
        metadata.tool_input = {};
        metadata.tool_input_truncated = true;
        metadata.tool_input_original_bytes = serialisedBytes(args);
        delete metadata.tool_input_truncated_keys;
        return;
      }
      const wire = mcpArgsForWire(args, budget);
      applyWireArgs(metadata, { ...wire, truncated: true, originalBytes: wire.originalBytes ?? serialisedBytes(args) });
    }
  } catch {
  }
}
function buildPromptPayload(input, profile) {
  const capped = capCommand(input.prompt, MAX_PROMPT_CHARS);
  const metadata = { cwd: input.cwd, has_ui: input.hasUI };
  if (capped.truncated) {
    metadata.prompt_truncated = true;
    metadata.prompt_original_chars = input.prompt.length;
  }
  const body = {
    conversation_id: input.sessionId,
    model: input.model !== void 0 && input.model.length > 0 ? input.model : "auto",
    event_name: EVENT_NAME_USER_PROMPT,
    pre_tool_use_data: { tool_name: "", command: "", metadata },
    messages: [{ role: "user", content: capped.command }],
    unbound_app_label: profile.appLabel,
    client_entrypoint: input.clientEntrypoint
  };
  if (input.pullPolicies === true) body.pull_policies = true;
  return withAccountIdentity(body, input.accountIdentity);
}

// packages/core/src/cache.ts
function expandTilde(raw, homeDir) {
  if (typeof raw !== "string") return void 0;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return void 0;
  if (trimmed === "~") return homeDir;
  if (trimmed.startsWith("~/")) return join2(homeDir, trimmed.slice(2));
  return trimmed;
}
function resolveCachePath(env, homeDir, profile) {
  let base;
  try {
    base = profile.resolveAgentDir(env, homeDir);
  } catch {
    return void 0;
  }
  if (typeof base !== "string" || base.length === 0 || !isAbsolute2(base)) return void 0;
  return join2(base, CACHE_DIR_NAME, CACHE_FILE_NAME);
}
function keyFingerprint(apiKey) {
  const material = typeof apiKey === "string" ? apiKey : "";
  return KEY_FINGERPRINT_PREFIX + createHash("sha256").update(material, "utf8").digest("hex").slice(0, 16);
}
function readCache(path, identity) {
  const raw = readSmallRegularFile(path, MAX_CACHE_BYTES);
  if (raw === void 0) return void 0;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return void 0;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return void 0;
  const body = parsed;
  const gatewayUrl = body.gateway_url;
  const fingerprint = body.key_fingerprint;
  if (typeof gatewayUrl !== "string" || gatewayUrl !== identity?.gatewayUrl) return void 0;
  if (typeof fingerprint !== "string" || fingerprint !== identity?.fingerprint) return void 0;
  const out = { gateway_url: gatewayUrl, key_fingerprint: fingerprint };
  const fetchedAt = parseTimestamp(body.fetched_at);
  if (fetchedAt !== void 0) out.fetched_at = fetchedAt;
  const action = parseFailureAction(body.policy_check_failure_action);
  if (action !== void 0) out.policy_check_failure_action = action;
  const tools = parseToolsToCheck(body.tools_to_check);
  const syncedAt = parseTimestamp(body.tools_synced_at);
  if (tools !== void 0 && syncedAt !== void 0) {
    out.tools_to_check = tools;
    out.tools_synced_at = syncedAt;
  }
  return out;
}
function writeCache(path, value) {
  let tmp;
  try {
    const dir = dirname(path);
    mkdirSync(dir, { recursive: true, mode: 448 });
    try {
      chmodSync(dir, 448);
    } catch {
    }
    tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
    writeFileSync(tmp, JSON.stringify(value), { encoding: "utf8", mode: 384 });
    try {
      chmodSync(tmp, 384);
    } catch {
    }
    try {
      renameSync(tmp, path);
    } catch {
      try {
        unlinkSync(path);
      } catch {
      }
      renameSync(tmp, path);
    }
    return true;
  } catch {
    if (tmp !== void 0) {
      try {
        unlinkSync(tmp);
      } catch {
      }
    }
    return false;
  }
}
function areToolsFresh(toolsSyncedAt, now, ttlMs = CACHE_TTL_MS) {
  const syncedAt = parseTimestamp(toolsSyncedAt);
  if (syncedAt === void 0) return false;
  const age = now - syncedAt;
  if (age < 0) return false;
  return age <= ttlMs;
}
function isToolsFresh(cache, now, ttlMs = CACHE_TTL_MS) {
  return areToolsFresh(cache?.tools_synced_at, now, ttlMs);
}
function shouldSkipFileTool(toolName, cache, now, fileTools) {
  if (typeof toolName !== "string" || !nativeFileTools(fileTools).has(toolName)) return false;
  if (!isToolsFresh(cache, now)) return false;
  const tools = cache?.tools_to_check;
  if (!Array.isArray(tools)) return false;
  return !tools.includes(toolName);
}
function shouldSkipFileToolFromState(toolName, state, now, fileTools) {
  return shouldSkipFileTool(
    toolName,
    { tools_synced_at: state.getToolsSyncedAt(), tools_to_check: state.getToolsToCheck() },
    now,
    fileTools
  );
}

// packages/core/src/client.ts
var MAX_ERRORS_PER_REQUEST = 10;
var MAX_ERROR_CLASS_CHARS = 40;
function classifyError(err) {
  let candidate = "";
  try {
    const record = err;
    const name = typeof record?.name === "string" ? record.name : "";
    const code = typeof record?.cause?.code === "string" ? record.cause.code : "";
    candidate = name === "TypeError" && code !== "" ? code : name !== "" ? name : code;
  } catch {
    candidate = "";
  }
  const token2 = candidate.replace(/[^A-Za-z0-9_]/g, "");
  return token2.length > 0 ? token2.slice(0, MAX_ERROR_CLASS_CHARS) : "Error";
}
function createApiClient(opts) {
  const timeoutMs = opts.timeoutMs ?? PRETOOL_TIMEOUT_MS;
  const errorsTimeoutMs = opts.errorsTimeoutMs ?? ERRORS_TIMEOUT_MS;
  const turnLogTimeoutMs = opts.turnLogTimeoutMs ?? TURNLOG_TIMEOUT_MS;
  const resolveFetch = () => opts.fetchImpl ?? globalThis.fetch;
  const headers = () => ({
    "content-type": "application/json",
    authorization: `Bearer ${opts.apiKey}`
  });
  async function postPretool(payload) {
    const startedAt = Date.now();
    const elapsed = () => Date.now() - startedAt;
    try {
      const res = await resolveFetch()(`${opts.baseUrl}${PRETOOL_PATH}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "error"
      });
      if (!res.ok) {
        return { ok: false, errorClass: `HttpStatus${res.status}`, elapsedMs: elapsed() };
      }
      let parsed;
      try {
        parsed = await res.json();
      } catch {
        return { ok: false, errorClass: "MalformedJson", elapsedMs: elapsed() };
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, errorClass: "MalformedJson", elapsedMs: elapsed() };
      }
      return { ok: true, body: parsed, elapsedMs: elapsed() };
    } catch (err) {
      return { ok: false, errorClass: classifyError(err), elapsedMs: elapsed() };
    }
  }
  async function postHookErrors(body) {
    try {
      const capped = {
        ...body,
        errors: body.errors.slice(0, MAX_ERRORS_PER_REQUEST)
      };
      const res = await resolveFetch()(`${opts.baseUrl}${ERRORS_PATH}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(capped),
        signal: AbortSignal.timeout(errorsTimeoutMs),
        redirect: "error"
      });
      return res.ok;
    } catch {
      return false;
    }
  }
  async function postTurnLog(body) {
    try {
      const res = await resolveFetch()(`${opts.baseUrl}${opts.profile.turnLogPath}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(turnLogTimeoutMs),
        redirect: "error"
      });
      return res.ok;
    } catch {
      return false;
    }
  }
  return { postPretool, postHookErrors, postTurnLog };
}

// packages/core/src/accountIdentity.ts
import { execFile as nodeExecFile } from "node:child_process";
import { tmpdir } from "node:os";
var PLACEHOLDERS = new Set(PLACEHOLDER_SERIALS);
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function label(value) {
  if (typeof value !== "string") return void 0;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_IDENTITY_FIELD_CHARS) return void 0;
  return trimmed;
}
function withDeadline(promise, ms, fallback) {
  return new Promise((resolve3) => {
    let timer;
    try {
      timer = setTimeout(() => resolve3(fallback), ms);
      timer.unref?.();
    } catch {
      resolve3(fallback);
      return;
    }
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve3(value);
      },
      () => {
        clearTimeout(timer);
        resolve3(fallback);
      }
    );
  });
}
function attempt(fn) {
  try {
    return fn();
  } catch (error) {
    return Promise.reject(error);
  }
}
async function fetchAnthropicProfile(token2, opts = {}) {
  try {
    if (typeof token2 !== "string" || token2.length === 0) return void 0;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const fetchImpl = opts.fetch ?? globalThis.fetch;
    const request = attempt(async () => {
      const res = await fetchImpl(opts.url ?? ANTHROPIC_PROFILE_URL, {
        method: "GET",
        headers: {
          authorization: `Bearer ${token2}`,
          [ANTHROPIC_OAUTH_BETA_HEADER]: ANTHROPIC_OAUTH_BETA_VALUE,
          accept: "application/json"
        },
        // The token must not follow a redirect anywhere, even same-origin.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (!res.ok) return void 0;
      const declared = Number(res.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_PROFILE_BYTES) return void 0;
      const text = await res.text();
      if (text.length > MAX_PROFILE_BYTES) return void 0;
      return parseProfile(JSON.parse(text));
    });
    return await withDeadline(request, timeoutMs, void 0);
  } catch {
    return void 0;
  }
}
function parseProfile(body) {
  if (!isRecord(body)) return void 0;
  const profile = {};
  const account = isRecord(body.account) ? body.account : {};
  const organization = isRecord(body.organization) ? body.organization : {};
  const email = label(account.email);
  if (email !== void 0 && email.includes("@")) profile.email = email;
  const orgId = label(organization.uuid);
  if (orgId !== void 0) profile.orgId = orgId;
  const plan = label(organization.organization_type);
  if (plan !== void 0) profile.plan = plan;
  return profile;
}
function emailDomain(email) {
  if (email === void 0) return void 0;
  const at = email.lastIndexOf("@");
  if (at === -1) return void 0;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domain.length > 0 ? domain : void 0;
}
function buildAccountIdentity(input) {
  try {
    if (!isRecord(input?.auth)) return void 0;
    const identity = {};
    const auth = input.auth;
    if (auth.hasCredential === true) {
      if (auth.anthropicOAuth === true) {
        identity.auth_mode = AUTH_MODE_SUBSCRIPTION;
        const profile = input.profile;
        const email = label(profile?.email);
        if (email !== void 0) {
          identity.user_email = email;
          const domain = emailDomain(email);
          if (domain !== void 0) identity.email_domain = domain;
        }
        const orgId = label(profile?.orgId);
        if (orgId !== void 0) identity.org_id = orgId;
        const plan = label(profile?.plan);
        if (plan !== void 0) identity.plan = plan;
      } else {
        identity.auth_mode = AUTH_MODE_API_KEY;
      }
    } else {
      const mode = label(auth.authMode);
      if (mode === AUTH_MODE_API_KEY) identity.auth_mode = mode;
      else if (mode === AUTH_MODE_SUBSCRIPTION && auth.provider === ANTHROPIC_PROVIDER_ID) identity.auth_mode = mode;
    }
    const serial = label(input.deviceSerial);
    if (serial !== void 0 && isValidSerial(serial)) identity.device_serial = serial;
    return Object.keys(identity).length > 0 ? identity : void 0;
  } catch {
    return void 0;
  }
}
function isValidSerial(value) {
  return typeof value === "string" && value.trim() !== "" && !PLACEHOLDERS.has(value.trim().toLowerCase());
}
function probeToolPath(tool, env = process.env) {
  switch (tool) {
    case "system_profiler":
      return "/usr/sbin/system_profiler";
    case "dmidecode":
      return "/usr/sbin/dmidecode";
    case "powershell": {
      const root = typeof env.SystemRoot === "string" && env.SystemRoot.trim() !== "" ? env.SystemRoot : "C:\\Windows";
      return `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    }
  }
}
var defaultExecFile = (file, args, opts) => new Promise((resolve3) => {
  try {
    nodeExecFile(
      file,
      [...args],
      { timeout: opts.timeoutMs, maxBuffer: opts.maxBytes, windowsHide: true, encoding: "utf8", cwd: tmpdir() },
      (error, stdout) => resolve3(error === null && typeof stdout === "string" ? stdout : void 0)
    );
  } catch {
    resolve3(void 0);
  }
});
function firstValid(stdout) {
  return stdout !== void 0 && isValidSerial(stdout) ? stdout.trim() : void 0;
}
async function probeSerial(opts, timeoutMs) {
  const run = opts.execFile ?? defaultExecFile;
  const exec = (file, args) => attempt(() => run(file, args, { timeoutMs, maxBytes: MAX_SERIAL_PROBE_BYTES })).catch(() => void 0);
  const platform = opts.platform ?? process.platform;
  if (platform === "darwin") {
    const out = await exec(probeToolPath("system_profiler"), ["SPHardwareDataType"]);
    for (const line of (out ?? "").split("\n")) {
      if (!line.includes("Serial Number")) continue;
      const sep = line.indexOf(": ");
      if (sep === -1) continue;
      const value = line.slice(sep + 2);
      if (isValidSerial(value)) return value.trim();
    }
    return void 0;
  }
  if (platform === "linux") {
    const dmi = firstValid(await exec(probeToolPath("dmidecode"), ["-s", "system-serial-number"]));
    if (dmi !== void 0) return dmi;
    const read = opts.readFile ?? ((path) => readSmallRegularFile(path, 4096));
    for (const path of LINUX_MACHINE_ID_PATHS) {
      try {
        const value = firstValid(read(path));
        if (value !== void 0) return value;
      } catch {
      }
    }
    return void 0;
  }
  if (platform === "win32") {
    const bios = firstValid(
      await exec(probeToolPath("powershell"), ["-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"])
    );
    if (bios !== void 0) return bios;
    return firstValid(
      await exec(probeToolPath("powershell"), [
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid"
      ])
    );
  }
  return void 0;
}
async function readDeviceSerial(opts = {}) {
  try {
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    return await withDeadline(attempt(() => probeSerial(opts, timeoutMs)), timeoutMs, void 0);
  } catch {
    return void 0;
  }
}
function createAccountIdentityLoader(opts) {
  let pending;
  let settled;
  async function compute(modelProvider) {
    let auth;
    try {
      auth = opts.readAuth(opts.agentDir, modelProvider);
    } catch {
      auth = void 0;
    }
    if (!isRecord(auth)) return void 0;
    const now = (opts.now ?? Date.now)();
    const token2 = auth.hasCredential === true && auth.anthropicOAuth === true && typeof auth.accessToken === "string" && auth.accessToken.length > 0 && typeof auth.expiresAt === "number" && auth.expiresAt > now ? auth.accessToken : void 0;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const [profile, deviceSerial] = await Promise.all([
      token2 !== void 0 ? fetchAnthropicProfile(token2, {
        timeoutMs,
        ...opts.fetch === void 0 ? {} : { fetch: opts.fetch },
        ...opts.profileUrl === void 0 ? {} : { url: opts.profileUrl }
      }) : Promise.resolve(void 0),
      readDeviceSerial({ ...opts, timeoutMs })
    ]);
    return buildAccountIdentity({
      auth,
      ...profile === void 0 ? {} : { profile },
      ...deviceSerial === void 0 ? {} : { deviceSerial }
    });
  }
  return {
    start(modelProvider) {
      if (pending === void 0) {
        pending = attempt(() => compute(modelProvider)).catch(() => void 0).then((identity) => {
          settled = identity;
          return identity;
        });
      }
      return pending;
    },
    current() {
      return settled;
    }
  };
}

// packages/core/src/keyState.ts
var REJECTION_LABELS = /* @__PURE__ */ new Set(["HttpStatus401", "HttpStatus403"]);
function createKeyState(opts = {}) {
  const threshold = typeof opts.threshold === "number" && opts.threshold > 0 ? opts.threshold : KEY_REJECTION_THRESHOLD;
  let consecutiveRejections = 0;
  let inactive = false;
  return {
    recordFailure(errorClass, opts2 = {}) {
      if (inactive) return void 0;
      if (typeof errorClass !== "string" || !REJECTION_LABELS.has(errorClass)) {
        consecutiveRejections = 0;
        return void 0;
      }
      consecutiveRejections += 1;
      if (consecutiveRejections < threshold) return void 0;
      if (opts2.failClosed === true) {
        consecutiveRejections = threshold;
        return "rejected";
      }
      inactive = true;
      return "inactive";
    },
    recordSuccess() {
      if (inactive) return;
      consecutiveRejections = 0;
    },
    isInactive: () => inactive
  };
}
var keyState = createKeyState();

// packages/core/src/verdict.ts
var CONTROL_CHARS = new RegExp(
  "[\\x00-\\x09\\x0b-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]",
  "g"
);
var UNICODE_LINE_SEPARATORS = new RegExp("[\\u2028\\u2029]", "g");
function parseDecision(raw) {
  if (raw === "allow" || raw === "deny" || raw === "ask" || raw === "approval_required") {
    return raw;
  }
  return void 0;
}
function sanitizeReason(raw) {
  if (typeof raw !== "string") return void 0;
  const stripped = raw.replace(CONTROL_CHARS, "").replace(UNICODE_LINE_SEPARATORS, " ");
  if (stripped.length === 0) return void 0;
  return stripped.length > MAX_REASON_CHARS ? stripped.slice(0, MAX_REASON_CHARS) : stripped;
}
function mapResponseToOutcome(body) {
  if (body === null || typeof body !== "object") return { kind: "allow" };
  const record = body;
  const decision = parseDecision(record["decision"]);
  if (decision === "deny") return { kind: "deny", reason: sanitizeReason(record["reason"]) };
  if (decision === "ask" || decision === "approval_required") {
    return { kind: "confirm", reason: sanitizeReason(record["reason"]) };
  }
  return { kind: "allow" };
}

// packages/core/src/policy.ts
function notify(hooks, message, level) {
  try {
    hooks?.notify?.(message, level);
  } catch {
  }
}
function createPolicyChecker(opts) {
  const breaker = opts.breaker ?? createBreaker({ now: opts.now });
  const keyState2 = opts.keyState ?? createKeyState();
  async function checkTool(payload, toolName, hooks) {
    try {
      if (keyState2.isInactive()) return { kind: "allow" };
      const breakerApplies = opts.state.getFailureAction() !== "block";
      if (breakerApplies && breaker.shouldSkip()) return { kind: "allow" };
      const res = await opts.client.postPretool(payload);
      if (res.ok) {
        keyState2.recordSuccess();
        if (breakerApplies) {
          const closed = breaker.recordSuccess();
          if (closed !== void 0) notify(hooks, BREAKER_CLOSED_NOTICE, "info");
        }
        opts.state.recordSuccess(res.body, (opts.now ?? Date.now)());
        if (opts.onSync !== void 0) {
          try {
            opts.onSync(opts.state.snapshot());
          } catch {
          }
        }
        return mapResponseToOutcome(res.body);
      }
      if (breakerApplies) {
        const opened = breaker.recordFailure();
        if (opened !== void 0) notify(hooks, BREAKER_OPEN_NOTICE, "warning");
      }
      const blocked = opts.state.getFailureAction() === "block";
      const rejection = keyState2.recordFailure(res.errorClass, { failClosed: blocked });
      if (rejection === "inactive") {
        notify(hooks, KEY_REJECTED_NOTICE, "warning");
        return { kind: "allow" };
      }
      opts.telemetry.reportBypass({
        errorClass: res.errorClass,
        toolName,
        elapsedMs: res.elapsedMs,
        blocked
      });
      if (!blocked) return { kind: "allow" };
      return rejection === "rejected" ? { kind: "unavailable", reason: KEY_REJECTED_BLOCK_REASON } : { kind: "unavailable" };
    } catch {
      return { kind: "allow" };
    }
  }
  return { checkTool };
}

// packages/core/src/scopedState.ts
function scopeKey(baseUrl, apiKey) {
  try {
    const url = normalizeGatewayUrl(baseUrl);
    if (url === void 0) return void 0;
    if (typeof apiKey !== "string" || apiKey.trim() === "") return void 0;
    return `${url} ${keyFingerprint(apiKey)}`;
  } catch {
    return void 0;
  }
}
function createScopedStates(opts = {}) {
  const keyStateOptions = opts?.keyState;
  const fresh = () => Object.freeze({ policy: createPolicyState(), key: createKeyState(keyStateOptions ?? {}) });
  const scopes = createKeyedState({
    max: opts?.max ?? MAX_TRACKED_SCOPES,
    create: fresh,
    fallback: fresh
  });
  return {
    forScope: (baseUrl, apiKey) => scopes.get(scopeKey(baseUrl, apiKey)),
    peek: (baseUrl, apiKey) => scopes.peek(scopeKey(baseUrl, apiKey)),
    release: (baseUrl, apiKey) => scopes.release(scopeKey(baseUrl, apiKey)),
    clear: () => scopes.clear(),
    size: () => scopes.size(),
    keys: () => scopes.keys()
  };
}

// packages/core/src/sessionState.ts
import { isAbsolute as isAbsolute3, resolve } from "node:path";

// packages/core/src/heartbeat.ts
function buildHeartbeatPayload(input, profile) {
  const body = {
    conversation_id: input.sessionId,
    model: input.model !== void 0 && input.model.length > 0 ? input.model : TURNLOG_MODEL,
    event_name: EVENT_NAME_SESSION_START,
    // Blank tool name, blank command, no `file_path`. See the header: this is what keeps the request
    // out of the command-policy evaluator.
    pre_tool_use_data: {
      tool_name: "",
      command: "",
      metadata: { cwd: input.cwd, has_ui: input.hasUI, [profile.versionMetadataKey]: input.agentVersion }
    },
    // Empty rather than absent: the field is required by the server type, and a heartbeat has no
    // prompt to report. Sending a blank prompt through the guardrail path is exactly what §C2 warns
    // against, which is why `event_name` above is not `user_prompt`.
    messages: [],
    unbound_app_label: profile.appLabel,
    client_entrypoint: input.clientEntrypoint,
    // Harmless here (the fall-through attaches no payload) and future-proof if the API later answers
    // this shape with one — at which point `recordSuccess` already handles the fields correctly.
    pull_policies: true,
    first_approval_check: true
  };
  return withAccountIdentity(body, input.accountIdentity);
}
function createHeartbeatGate(opts) {
  let lastSentAt;
  return {
    shouldSend(fetchedAt) {
      try {
        if (lastSentAt === void 0) return true;
        if (fetchedAt === void 0 || !Number.isFinite(fetchedAt)) return false;
        const now = opts.now();
        if (now - fetchedAt <= opts.ttlMs) return false;
        return now - lastSentAt > opts.ttlMs;
      } catch {
        return false;
      }
    },
    markSent() {
      try {
        lastSentAt = opts.now();
      } catch {
        lastSentAt = Number.MAX_SAFE_INTEGER;
      }
    }
  };
}

// packages/core/src/turn.ts
import { createHash as createHash2 } from "node:crypto";
var EMPTY_PROJECTION = { prefix: "", body: "" };
function projectPart(part) {
  if (part === null || typeof part !== "object") return EMPTY_PROJECTION;
  const record = part;
  if (record.type === "image") {
    const mimeType = typeof record.mimeType === "string" ? record.mimeType : "";
    const data = typeof record.data === "string" ? record.data : "";
    return { prefix: `image:${mimeType}:`, body: data };
  }
  const text = typeof record.text === "string" ? record.text : "";
  return { prefix: "text:", body: text };
}
function projectionByteLength(projection) {
  return Buffer.byteLength(projection.prefix, "utf8") + Buffer.byteLength(projection.body, "utf8");
}
function hashContent(parts) {
  try {
    const list = Array.isArray(parts) ? parts : [];
    let bytes = 0;
    for (let i = 0; i < list.length; i += 1) {
      if (i > 0) bytes += 1;
      bytes += projectionByteLength(projectPart(list[i]));
    }
    if (bytes > MAX_HASH_BYTES) {
      return { content_sha256: void 0, content_bytes: bytes, hash_skipped: true };
    }
    const hash = createHash2("sha256");
    for (let i = 0; i < list.length; i += 1) {
      if (i > 0) hash.update("\n", "utf8");
      const projection = projectPart(list[i]);
      hash.update(projection.prefix, "utf8");
      hash.update(projection.body, "utf8");
    }
    return { content_sha256: hash.digest("hex"), content_bytes: bytes };
  } catch {
    return { content_sha256: void 0, content_bytes: 0, hash_skipped: true };
  }
}
function copyInput(input) {
  try {
    return structuredClone(input);
  } catch {
    return { ...input };
  }
}
function createTurnStore() {
  let record = { tool_calls: [], results: [] };
  let outputChars = 0;
  const fresh = () => {
    outputChars = 0;
    return { tool_calls: [], results: [] };
  };
  const started = () => record.prompt !== void 0 || record.tool_calls.length > 0;
  const idOf = (sessionId) => typeof sessionId === "string" && sessionId !== "" ? sessionId : void 0;
  function startTurn(sessionId, now) {
    const incoming = idOf(sessionId);
    if (incoming !== void 0 && record.session_id !== void 0 && record.session_id !== incoming) {
      record = fresh();
    }
    if (incoming !== void 0) {
      const ours = record.tool_calls.filter(
        (entry) => entry.session_id === void 0 || entry.session_id === incoming
      );
      if (ours.length !== record.tool_calls.length) record.tool_calls = ours;
    }
    if (record.session_id === void 0 && incoming !== void 0) {
      record.session_id = incoming;
    }
    if (record.started_at === void 0 && typeof now === "number" && Number.isFinite(now)) {
      record.started_at = now;
    }
  }
  return {
    startTurn,
    reset(sessionId) {
      try {
        const incoming = idOf(sessionId);
        if (incoming === void 0) return;
        if (record.session_id === incoming) return;
        record = fresh();
      } catch {
      }
    },
    recordPrompt(text, sessionId, now = Date.now()) {
      try {
        startTurn(sessionId, now);
        record.prompt = typeof text === "string" ? text : "";
      } catch {
      }
    },
    /**
     * Capped at `MAX_TURN_TOOL_CALLS`, dropping the oldest, exactly as `recordResult` caps `results`
     * (WR-04). `user_bash` is why: it records a call, pi fires no `agent_end` for a bare `!cmd`, so
     * nothing drains the record and a developer working through a series of them accumulated an entry
     * per invocation for the whole session.
     */
    recordToolCall(entry, sessionId, now = Date.now()) {
      try {
        if (entry === null || typeof entry !== "object") return;
        startTurn(sessionId, now);
        while (record.tool_calls.length >= MAX_TURN_TOOL_CALLS) {
          record.tool_calls.shift();
          record.tool_calls_truncated = (record.tool_calls_truncated ?? 0) + 1;
        }
        const stored = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          decision: typeof entry.decision === "string" ? entry.decision : "",
          ts: now
        };
        const input = entry.tool_input;
        if (input !== null && typeof input === "object" && !Array.isArray(input)) {
          stored.tool_input = { ...input };
        }
        const incoming = idOf(sessionId);
        if (incoming !== void 0) stored.session_id = incoming;
        record.tool_calls.push(stored);
      } catch {
      }
    },
    /**
     * A result does **not** start a turn. A tool result whose call was never recorded belongs to a
     * turn already posted (or to one this process never saw), and starting a turn from it would post
     * a record with no prompt and no call — exactly the noise `PY:4975` refuses to send.
     *
     * Capped at `MAX_TURN_RESULTS`, dropping the oldest: the newest results are the ones a developer
     * is looking at, and an early call that loses its digest gets an honest empty `tool_response`
     * rather than another call's. The caller is expected not to record at all when nothing will post
     * the record (`index.ts` does exactly that for a keyless or latched session) — this is the
     * backstop for the turn that legitimately produces more results than anyone wants to read.
     */
    recordResult(entry) {
      try {
        if (entry === null || typeof entry !== "object") return;
        while (record.results.length >= MAX_TURN_RESULTS) {
          const evicted = record.results.shift();
          record.results_truncated = (record.results_truncated ?? 0) + 1;
          if (typeof evicted?.content === "string") outputChars = Math.max(0, outputChars - evicted.content.length);
        }
        const stored = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          is_error: entry.is_error === true,
          content_bytes: typeof entry.content_bytes === "number" ? entry.content_bytes : 0
        };
        if (typeof entry.content_sha256 === "string") stored.content_sha256 = entry.content_sha256;
        if (entry.hash_skipped === true) stored.hash_skipped = true;
        const id = stored.tool_use_id;
        const recorded = id !== "" && record.tool_calls.some((call) => call.tool_use_id === id);
        if (!recorded) {
        } else if (typeof entry.content === "string") {
          if (outputChars + entry.content.length > MAX_TURN_OUTPUT_CHARS) {
            stored.content_omitted = true;
          } else {
            stored.content = entry.content;
            outputChars += entry.content.length;
            if (entry.content_truncated === true) stored.content_truncated = true;
            if (typeof entry.content_original_chars === "number" && Number.isFinite(entry.content_original_chars)) {
              stored.content_original_chars = entry.content_original_chars;
            }
          }
        } else if (entry.content_omitted === true) {
          stored.content_omitted = true;
        }
        record.results.push(stored);
      } catch {
      }
    },
    /**
     * Consumes the record unconditionally, and answers `undefined` when there was nothing postable.
     *
     * The reset is NOT conditional on the record being postable, and that is the point. A turn can
     * collect results without ever starting — a custom tool (or an MCP call nobody could resolve)
     * takes the nothing-evaluable skip and records no decision, an extension-sourced prompt records
     * no prompt — and an early return here left those results in place, where `agent_end` could
     * never drain them. They then belonged to no turn at all: `shouldPostTurn` refuses to send them, and a later started turn would only
     * fail to match them by `tool_use_id`. Consumed and dropped is the honest outcome.
     */
    take() {
      try {
        const taken = record;
        const postable = started();
        record = fresh();
        return postable ? taken : void 0;
      } catch {
        return void 0;
      }
    },
    isEmpty() {
      try {
        return !started();
      } catch {
        return true;
      }
    },
    snapshot() {
      const copy = {
        // `tool_input` is copied a second time so `snapshot()` never hands callers a live reference
        // into the record. A native call's values are scalars (`sanitizeToolInput` forwards nothing
        // else), but an MCP call's capped arguments can nest, so the copy is structural.
        tool_calls: record.tool_calls.map(
          (entry) => entry.tool_input === void 0 ? { ...entry } : { ...entry, tool_input: copyInput(entry.tool_input) }
        ),
        results: record.results.map((entry) => ({ ...entry }))
      };
      if (record.prompt !== void 0) copy.prompt = record.prompt;
      if (record.session_id !== void 0) copy.session_id = record.session_id;
      if (record.started_at !== void 0) copy.started_at = record.started_at;
      if (record.results_truncated !== void 0) copy.results_truncated = record.results_truncated;
      if (record.tool_calls_truncated !== void 0) {
        copy.tool_calls_truncated = record.tool_calls_truncated;
      }
      return copy;
    },
    currentPrompt(sessionId) {
      try {
        const prompt = record.prompt;
        if (typeof prompt !== "string") return void 0;
        if (sessionId === "" || record.session_id === void 0 || record.session_id === sessionId) {
          return prompt;
        }
        return void 0;
      } catch {
        return void 0;
      }
    }
  };
}
var turnStore = createTurnStore();

// packages/core/src/sessionState.ts
function createSessionStates(opts = {}) {
  const states = createKeyedState({
    max: opts?.max ?? MAX_TRACKED_SESSIONS,
    create: (id) => ({ sessionId: id, turn: createTurnStore() }),
    fallback: () => ({ sessionId: "", turn: createTurnStore() })
  });
  return {
    forSession: (id) => states.get(id),
    release: (id) => states.release(id),
    clear: () => states.clear(),
    size: () => states.size()
  };
}
function directoryKey(dir) {
  try {
    if (typeof dir !== "string" || dir === "" || !isAbsolute3(dir)) return void 0;
    const key = resolve(dir);
    return key === "" ? void 0 : key;
  } catch {
    return void 0;
  }
}
function createInstanceStates(opts = {}) {
  const now = typeof opts?.now === "function" ? opts.now : Date.now;
  const ttlMs = typeof opts?.ttlMs === "number" && opts.ttlMs > 0 ? opts.ttlMs : CACHE_TTL_MS;
  const fresh = (directory) => ({
    directory,
    heartbeatGate: createHeartbeatGate({ now, ttlMs }),
    noKeyNoticeShown: false
  });
  const states = createKeyedState({
    max: opts?.max ?? MAX_TRACKED_INSTANCES,
    normalizeKey: directoryKey,
    create: fresh,
    fallback: () => fresh("")
  });
  return {
    forDirectory: (dir) => states.get(dir),
    release: (dir) => states.release(dir),
    clear: () => states.clear(),
    size: () => states.size()
  };
}

// packages/core/src/signals.ts
var MAX_SIGNAL_CATEGORIES = 32;
var MAX_SIGNAL_DETAIL_CHARS = 100;
var CATEGORY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
var UNSAFE_DETAIL_CHARS = /[^A-Za-z0-9_.:/-]/g;
function token(value, apiKey, fallback) {
  if (typeof value !== "string") return fallback;
  const reduced = redactSecrets(value, apiKey).replace(UNSAFE_DETAIL_CHARS, "").slice(0, MAX_SIGNAL_DETAIL_CHARS);
  return reduced === "" ? fallback : reduced;
}
function readField(ctx, field) {
  try {
    if (ctx === null || typeof ctx !== "object") return void 0;
    return ctx[field];
  } catch {
    return void 0;
  }
}
function createSignalReporter(opts) {
  const now = opts.now ?? Date.now;
  const rawInterval = opts.intervalMs;
  const intervalMs = typeof rawInterval === "number" && Number.isFinite(rawInterval) && rawInterval >= 0 ? rawInterval : ERROR_REPORT_INTERVAL_MS;
  const lastReportAtMs = /* @__PURE__ */ new Map();
  const inFlight = /* @__PURE__ */ new Set();
  function report(category, ctx) {
    try {
      const apiKey = opts.apiKey;
      if (typeof apiKey !== "string" || apiKey === "") return;
      if (typeof category !== "string" || !CATEGORY_PATTERN.test(category)) return;
      if (opts.isInactive?.() === true) return;
      if (inFlight.has(category)) return;
      const last = lastReportAtMs.get(category);
      if (last === void 0 && lastReportAtMs.size >= MAX_SIGNAL_CATEGORIES) return;
      const at = now();
      if (typeof at !== "number" || !Number.isFinite(at)) return;
      if (last !== void 0 && at - last < intervalMs) return;
      lastReportAtMs.set(category, at);
      const toolName = token(readField(ctx, "toolName"), apiKey, "unknown");
      const detail = token(readField(ctx, "detail"), apiKey, "unspecified");
      const message = redactSecrets(
        `${opts.profile.hookSource} hook ${category}: ${detail} for tool=${toolName}`,
        apiKey
      );
      const body = {
        errors: [{ message, timestamp: new Date(at).toISOString(), category }],
        hook_source: opts.profile.hookSource
      };
      inFlight.add(category);
      let posted;
      try {
        posted = Promise.resolve(opts.client.postHookErrors(body));
      } catch {
        inFlight.delete(category);
        return;
      }
      void posted.catch(() => false).finally(() => {
        inFlight.delete(category);
      });
    } catch {
      inFlight.delete(category);
    }
  }
  return { report };
}

// packages/core/src/telemetry.ts
function createTelemetry(opts) {
  const now = opts.now ?? Date.now;
  const intervalMs = opts.intervalMs ?? ERROR_REPORT_INTERVAL_MS;
  let lastReportAtMs;
  let reporting = false;
  function report(category, ctx) {
    try {
      const apiKey = opts.apiKey;
      if (apiKey === void 0 || apiKey === "") return;
      if (opts.isInactive?.() === true) return;
      if (reporting) return;
      const at = now();
      if (lastReportAtMs !== void 0 && at - lastReportAtMs < intervalMs) return;
      lastReportAtMs = at;
      reporting = true;
      const message = redactSecrets(
        `${opts.profile.hookSource} hook ${category}: ${ctx.errorClass} for tool=${ctx.toolName} after ${ctx.elapsedMs}ms`,
        apiKey
      );
      const body = {
        errors: [{ message, timestamp: new Date(at).toISOString(), category }],
        hook_source: opts.profile.hookSource
      };
      void opts.client.postHookErrors(body).catch(() => false).finally(() => {
        reporting = false;
      });
    } catch {
      reporting = false;
    }
  }
  return {
    reportBypass(ctx) {
      report(ctx.blocked === true ? ERROR_CATEGORY_BLOCKED : ERROR_CATEGORY_BYPASS, ctx);
    },
    reportTurnLogFailure(ctx) {
      report(ERROR_CATEGORY_TURNLOG, ctx);
    }
  };
}

// packages/opencode/src/auth.ts
import { join as join3 } from "node:path";
var AUTH_TYPE_OAUTH = "oauth";
function isRecord2(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function parseStore(raw) {
  if (raw === void 0) return void 0;
  try {
    const parsed = JSON.parse(raw);
    return isRecord2(parsed) ? parsed : void 0;
  } catch {
    return void 0;
  }
}
function envContent(env) {
  try {
    if (env === null || typeof env !== "object") return void 0;
    const raw = env[ENV_OPENCODE_AUTH_CONTENT];
    if (typeof raw !== "string" || raw === "" || raw.length > MAX_AUTH_FILE_BYTES) return void 0;
    return raw;
  } catch {
    return void 0;
  }
}
function readTypes(dataDir, env) {
  let store = parseStore(envContent(env));
  if (store === void 0) {
    if (typeof dataDir !== "string" || dataDir === "") return void 0;
    store = parseStore(readSmallRegularFile(join3(dataDir, AUTH_FILE_NAME), MAX_AUTH_FILE_BYTES));
  }
  if (store === void 0) return void 0;
  const types = /* @__PURE__ */ new Map();
  for (const name of Object.keys(store)) {
    const entry = store[name];
    if (!isRecord2(entry)) continue;
    const type = entry.type;
    if (typeof type === "string" && type !== "") types.set(name, type);
  }
  return types;
}
function readOpencodeAuthSummary(dataDir, modelProvider, env) {
  try {
    const types = readTypes(dataDir, env);
    if (types === void 0) return void 0;
    const named = label(modelProvider);
    const provider = named ?? (types.size === 1 ? [...types.keys()][0] : void 0);
    const type = provider === void 0 ? void 0 : types.get(provider);
    return {
      provider,
      hasCredential: type !== void 0,
      anthropicOAuth: type === AUTH_TYPE_OAUTH
    };
  } catch {
    return void 0;
  }
}

// packages/core/src/evaluate.ts
var HOST_GENERATED_SOURCE = "extension";
var MAX_TIMER_MS = 2147483647;
function noteSafe(fn) {
  try {
    fn?.();
  } catch {
  }
}
function noteDecision(deps, entry) {
  noteSafe(() => deps.onDecision?.(entry));
}
function isRecord3(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function asString(value) {
  return typeof value === "string" ? value : "";
}
function readPrompt(source) {
  try {
    return asString(source.lastUserPrompt);
  } catch {
    return "";
  }
}
function resolveState(raw) {
  return raw !== null && typeof raw === "object" ? raw : createPolicyState();
}
function resolveDeadlineMs(raw) {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return Math.min(raw, MAX_TIMER_MS);
  return PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS;
}
function safeHooks(hooks) {
  if (hooks === void 0 || hooks === null) return void 0;
  return {
    notify(message, level) {
      noteSafe(() => hooks.notify?.(message, level));
    }
  };
}
function raceDeadline(start, deadlineMs) {
  return new Promise((resolve3) => {
    let done = false;
    let timer;
    const finish = (result) => {
      if (done) return;
      done = true;
      if (timer !== void 0) clearTimeout(timer);
      resolve3(result);
    };
    try {
      timer = setTimeout(() => finish({ state: "timed-out" }), deadlineMs);
      Promise.resolve(start()).then(
        (value) => finish({ state: "answered", value }),
        () => finish({ state: "faulted" })
      );
    } catch {
      finish({ state: "faulted" });
    }
  });
}
function normaliseOutcome(raw) {
  if (raw === null || typeof raw !== "object") return { kind: "allow" };
  const kind = raw.kind;
  if (kind !== "deny" && kind !== "confirm" && kind !== "unavailable") return { kind: "allow" };
  const reason = raw.reason;
  return typeof reason === "string" ? { kind, reason } : { kind };
}
async function check(payload, label2, deps, state) {
  const hooks = safeHooks(deps.hooks);
  const deadlineMs = resolveDeadlineMs(deps.deadlineMs);
  const raced = await raceDeadline(() => deps.checker.checkTool(payload, label2, hooks), deadlineMs);
  if (raced.state === "answered") return normaliseOutcome(raced.value);
  if (raced.state === "faulted") return void 0;
  const blocked = state.getFailureAction() === "block";
  noteSafe(
    () => deps.telemetry?.reportBypass({
      errorClass: EVALUATE_DEADLINE_ERROR_CLASS,
      toolName: label2,
      elapsedMs: deadlineMs,
      blocked
    })
  );
  return blocked ? { kind: "unavailable" } : { kind: "allow" };
}
async function evaluateToolCall(call, deps) {
  try {
    const source = isRecord3(call) ? call : {};
    const toolName = asString(source.toolName);
    const toolCallId = asString(source.toolCallId);
    const command = asString(source.command);
    const toolInput = isRecord3(source.toolInput) ? source.toolInput : {};
    const cwd = asString(source.cwd);
    const profile = deps.profile;
    const mcp = normaliseMcp(source.mcp);
    const filePath = resolveFilePath(toolName, toolInput, cwd, profile.fileTools);
    const sendUnattributed = source.sendUnattributed === true;
    if (!sendUnattributed && command.trim() === "" && filePath === void 0 && mcp === void 0) {
      return { kind: "skip", why: "nothing-evaluable" };
    }
    const extraKeys = profileExtraToolInputKeys(profile);
    const auditInput = auditToolInput(toolInput, command, extraKeys);
    const now = (deps.now ?? Date.now)();
    const state = resolveState(deps.state);
    const toolsConfirmed = state.getToolsConfirmed();
    if (toolsConfirmed && nativeFileTools(profile.fileTools).has(toolName) && shouldSkipFileToolFromState(toolName, state, now, profile.fileTools)) {
      noteDecision(deps, {
        tool_name: toolName,
        tool_use_id: toolCallId,
        decision: "skipped",
        tool_input: auditInput
      });
      return { kind: "skip", why: "cached" };
    }
    const pullPolicies = !toolsConfirmed || !areToolsFresh(state.getToolsSyncedAt(), now);
    const model = source.model;
    const payload = buildPretoolPayload({
      toolName,
      command,
      toolUseId: toolCallId,
      toolInput,
      cwd,
      sessionId: asString(source.sessionId),
      model: typeof model === "string" ? model : void 0,
      clientEntrypoint: asString(deps.entrypoint),
      pullPolicies,
      lastUserPrompt: readPrompt(source),
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity },
      ...mcp === void 0 ? {} : { mcp: { server: mcp.server, tool: mcp.tool ?? "" } },
      ...source.patchOperation === "delete" ? { patchOperation: "delete" } : {}
    }, profile);
    const outcome = await check(payload, toolName, deps, state);
    if (outcome === void 0) return { kind: "allow" };
    noteDecision(deps, {
      tool_name: toolName,
      tool_use_id: toolCallId,
      decision: outcome.kind,
      tool_input: auditInput
    });
    return outcome;
  } catch {
    return { kind: "allow" };
  }
}
async function evaluatePrompt(input, deps) {
  try {
    const source = isRecord3(input) ? input : {};
    if (source.source === HOST_GENERATED_SOURCE) return { kind: "skip", why: "nothing-evaluable" };
    const prompt = asString(source.text);
    if (prompt.trim() === "") return { kind: "skip", why: "nothing-evaluable" };
    const state = resolveState(deps.state);
    const model = source.model;
    const payload = buildPromptPayload({
      prompt,
      cwd: asString(source.cwd),
      sessionId: asString(source.sessionId),
      model: typeof model === "string" ? model : void 0,
      clientEntrypoint: asString(deps.entrypoint),
      hasUI: source.hasUI === true,
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    }, deps.profile);
    const outcome = await check(payload, "user_prompt", deps, state);
    return outcome ?? { kind: "allow" };
  } catch {
    return { kind: "allow" };
  }
}
function verdictMessage(verdict) {
  try {
    if (verdict === null || typeof verdict !== "object") return GENERIC_DENY_REASON;
    const kind = verdict.kind;
    if (kind === "allow" || kind === "skip") return "";
    const reason = sanitizeReason(verdict.reason);
    if (kind === "deny") return reason === void 0 ? GENERIC_DENY_REASON : DENY_PREFIX + reason;
    if (kind === "unavailable") return reason ?? ENGINE_UNAVAILABLE_REASON;
    return reason ?? GENERIC_DENY_REASON;
  } catch {
    return GENERIC_DENY_REASON;
  }
}

// packages/opencode/src/block.ts
function block(message) {
  const text = typeof message === "string" && message.length > 0 ? message : GENERIC_DENY_REASON;
  const err = new Error(text);
  try {
    err.stack = text;
  } catch {
  }
  throw err;
}

// packages/opencode/src/narrow.ts
import { createHash as createHash3 } from "node:crypto";
import { isAbsolute as isAbsolute4 } from "node:path";
var SHELL_TOOLS = /* @__PURE__ */ new Set(["bash"]);
var TASK_TOOL = "task";
var MCP_RESOURCE_TOOLS = /* @__PURE__ */ new Set([
  "list_mcp_resources",
  "list_mcp_resource_templates",
  "read_mcp_resource"
]);
var BUILTIN_TOOLS = /* @__PURE__ */ new Set([
  "bash",
  "read",
  "write",
  "edit",
  "apply_patch",
  "glob",
  "grep",
  "webfetch",
  "websearch",
  TASK_TOOL,
  "todowrite",
  "skill",
  "question",
  "invalid",
  "lsp",
  "plan_exit",
  "execute",
  ...MCP_RESOURCE_TOOLS
]);
var PATCH_HEADER_PREFIXES = Object.freeze([
  "*** Add File:",
  "*** Update File:",
  "*** Delete File:",
  "*** Move to:"
]);
var MAX_MCP_SERVERS = 1024;
var MAX_DIGEST_DEPTH = 32;
var MAX_DIGEST_CHARS = 1024 * 1024;
function readField2(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function nonBlank(value) {
  return typeof value === "string" && value.trim() !== "" ? value : void 0;
}
function shellCommandOf(tool, args) {
  try {
    if (typeof tool !== "string" || !SHELL_TOOLS.has(tool)) return "";
    const command = readField2(args, "command");
    return typeof command === "string" ? command : "";
  } catch {
    return "";
  }
}
function shellCwdOf(args, directory) {
  const fallback = typeof directory === "string" ? directory : "";
  try {
    const workdir = readField2(args, "workdir");
    return typeof workdir === "string" && workdir.length > 0 && isAbsolute4(workdir) ? workdir : fallback;
  } catch {
    return fallback;
  }
}
function applyPatchTargets(patchText) {
  try {
    if (typeof patchText !== "string" || patchText === "") return { targets: [], capped: false };
    const seen = /* @__PURE__ */ new Set();
    for (const raw of patchText.split(/\r?\n/)) {
      const line = raw.trimStart();
      if (!line.startsWith("***")) continue;
      const prefix = PATCH_HEADER_PREFIXES.find((p) => line.startsWith(p));
      if (prefix === void 0) continue;
      const path = line.slice(prefix.length).trim();
      if (path === "" || seen.has(path)) continue;
      if (seen.size >= MAX_PATCH_TARGETS) return { targets: [...seen], capped: true };
      seen.add(path);
    }
    return { targets: [...seen], capped: false };
  } catch {
    return { targets: [], capped: false };
  }
}
var PATCH_DELETE_PREFIX = "*** Delete File:";
function applyPatchDeletedPaths(patchText) {
  const deleted = /* @__PURE__ */ new Set();
  try {
    if (typeof patchText !== "string" || patchText === "") return deleted;
    for (const raw of patchText.split(/\r?\n/)) {
      const line = raw.trimStart();
      if (!line.startsWith(PATCH_DELETE_PREFIX)) continue;
      const path = line.slice(PATCH_DELETE_PREFIX.length).trim();
      if (path === "") continue;
      if (deleted.size >= MAX_PATCH_TARGETS) break;
      deleted.add(path);
    }
    return deleted;
  } catch {
    return deleted;
  }
}
function sanitizeMcpName(value) {
  return typeof value === "string" ? value.replace(/[^a-zA-Z0-9_-]/g, "_") : "";
}
function mcpCandidates(toolId, serverNames) {
  try {
    if (typeof toolId !== "string" || toolId === "" || !Array.isArray(serverNames)) return [];
    const found = /* @__PURE__ */ new Map();
    const count = Math.min(serverNames.length, MAX_MCP_SERVERS);
    for (let i = 0; i < count; i += 1) {
      const name = serverNames[i];
      if (typeof name !== "string" || name === "" || found.has(name)) continue;
      const prefix = `${sanitizeMcpName(name)}_`;
      if (toolId.length <= prefix.length || !toolId.startsWith(prefix)) continue;
      found.set(name, prefix.length);
    }
    return [...found.entries()].sort(([a, la], [b, lb]) => la !== lb ? lb - la : a < b ? -1 : a > b ? 1 : 0).map(([server, prefixLength]) => ({ server, tool: toolId.slice(prefixLength) }));
  } catch {
    return [];
  }
}
function mcpResourceTarget(tool, args) {
  try {
    if (typeof tool !== "string" || !MCP_RESOURCE_TOOLS.has(tool)) return void 0;
    const server = nonBlank(readField2(args, "server"));
    return server === void 0 ? void 0 : { server, tool };
  } catch {
    return void 0;
  }
}
function canonical(value, depth, ancestors, budget) {
  const charge = (text) => {
    budget.left -= text.length;
    return budget.left < 0 ? void 0 : text;
  };
  if (value === null) return charge("null");
  switch (typeof value) {
    case "string":
      if (value.length > budget.left) return void 0;
      return charge(JSON.stringify(value));
    case "number":
      return charge(Number.isFinite(value) ? String(value) : "null");
    case "boolean":
      return charge(value ? "true" : "false");
    case "bigint":
      return void 0;
    case "undefined":
    case "function":
    case "symbol":
      return "";
    default:
      break;
  }
  const obj = value;
  if (depth >= MAX_DIGEST_DEPTH || ancestors.has(obj)) return void 0;
  ancestors.add(obj);
  const parts = [];
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const part = canonical(item, depth + 1, ancestors, budget);
      if (part === void 0) return void 0;
      const element = part === "" ? charge("null") : part;
      if (element === void 0 || charge(",") === void 0) return void 0;
      parts.push(element);
    }
    ancestors.delete(obj);
    return charge("[]") === void 0 ? void 0 : `[${parts.join(",")}]`;
  }
  for (const key of Object.keys(obj).sort()) {
    const part = canonical(obj[key], depth + 1, ancestors, budget);
    if (part === void 0) return void 0;
    if (part === "") continue;
    const label2 = charge(`${JSON.stringify(key)}:,`);
    if (label2 === void 0) return void 0;
    parts.push(`${JSON.stringify(key)}:${part}`);
  }
  ancestors.delete(obj);
  return charge("{}") === void 0 ? void 0 : `{${parts.join(",")}}`;
}
function argsDigest(args) {
  try {
    const text = canonical(args, 0, /* @__PURE__ */ new Set(), { left: MAX_DIGEST_CHARS });
    if (text === void 0 || text === "") return void 0;
    return createHash3("sha256").update(text).digest("hex");
  } catch {
    return void 0;
  }
}

// packages/opencode/src/notify.ts
var TOAST_TITLE = "Unbound";
function showToastOf(client) {
  try {
    if (client === null || typeof client !== "object") return void 0;
    const tui = client.tui;
    if (tui === null || typeof tui !== "object") return void 0;
    const show = tui.showToast;
    return typeof show === "function" ? (opts) => show.call(tui, opts) : void 0;
  } catch {
    return void 0;
  }
}
function notify2(client, message, level) {
  try {
    const show = showToastOf(client);
    if (show === void 0 || typeof message !== "string" || message === "") return Promise.resolve();
    const toast = Promise.resolve(show({ body: { message, variant: level, title: TOAST_TITLE } }));
    return new Promise((resolve3) => {
      let timer;
      const done = () => {
        if (timer !== void 0) clearTimeout(timer);
        resolve3();
      };
      try {
        timer = setTimeout(done, TOAST_TIMEOUT_MS);
        timer.unref?.();
      } catch {
      }
      toast.then(done, done);
    });
  } catch {
    return Promise.resolve();
  }
}

// packages/opencode/src/profile.ts
import { isAbsolute as isAbsolute5, join as join4 } from "node:path";
function readEnv(env, name) {
  try {
    if (env === null || typeof env !== "object") return void 0;
    return env[name];
  } catch {
    return void 0;
  }
}
function absoluteOrUndefined(value) {
  return typeof value === "string" && value.length > 0 && isAbsolute5(value) ? value : void 0;
}
function xdgOpencodeDir(env, homeDir, envName, defaults) {
  const xdg = absoluteOrUndefined(readEnv(env, envName));
  if (xdg !== void 0) return join4(xdg, OPENCODE_DIR_NAME);
  const home = absoluteOrUndefined(homeDir);
  return home === void 0 ? void 0 : join4(home, ...defaults, OPENCODE_DIR_NAME);
}
function resolveOpencodeConfigDir(env, homeDir) {
  try {
    const home = typeof homeDir === "string" ? homeDir : "";
    const override = absoluteOrUndefined(expandTilde(readEnv(env, ENV_OPENCODE_CONFIG_DIR), home));
    if (override !== void 0) return override;
    return xdgOpencodeDir(env, homeDir, ENV_XDG_CONFIG_HOME, XDG_CONFIG_DEFAULT_SEGMENTS);
  } catch {
    return void 0;
  }
}
function resolveOpencodeDataDir(env, homeDir) {
  try {
    return xdgOpencodeDir(env, homeDir, ENV_XDG_DATA_HOME, XDG_DATA_DEFAULT_SEGMENTS);
  } catch {
    return void 0;
  }
}
var OPENCODE_PATH_DEFAULTING_TOOLS = ["grep", "glob"];
var OPENCODE_PATH_REQUIRED_TOOLS = ["read", "write", "edit", "lsp", "apply_patch"];
var PATH_KEYS = /* @__PURE__ */ new Map([
  ["read", ["filePath", "path"]],
  ["write", ["filePath", "path"]],
  ["edit", ["filePath", "path"]],
  ["lsp", ["filePath"]],
  ["apply_patch", ["filePath"]],
  ["grep", ["path"]],
  ["glob", ["path"]]
]);
var OPENCODE_FILE_TOOLS = Object.freeze({
  defaulting: new Set(OPENCODE_PATH_DEFAULTING_TOOLS),
  required: new Set(OPENCODE_PATH_REQUIRED_TOOLS),
  /** The first non-empty string under the tool's own keys; anything else is `undefined`. */
  pathOf(toolName, input) {
    try {
      const keys = typeof toolName === "string" ? PATH_KEYS.get(toolName) : void 0;
      if (keys === void 0 || input === null || typeof input !== "object") return void 0;
      for (const key of keys) {
        const value = input[key];
        if (typeof value === "string" && value.length > 0) return value;
      }
      return void 0;
    } catch {
      return void 0;
    }
  }
});
var EXTRA_TOOL_INPUT_KEYS = Object.freeze(["include"]);
var OPENCODE_PROFILE = Object.freeze({
  appLabel: "opencode",
  hookSource: "opencode-hook",
  turnLogPath: "/v1/hooks/opencode",
  envApiKey: "UNBOUND_OPENCODE_API_KEY",
  versionMetadataKey: "opencode_version",
  /**
   * Always `opencode/unknown` here: the host version is not on argv. The adapter learns it at runtime
   * from `session.created` (`oc:schema/src/v1/session.ts:558`) and builds `opencode/<version>` itself.
   */
  resolveClientEntrypoint() {
    return UNKNOWN_ENTRYPOINT;
  },
  resolveAgentDir: resolveOpencodeConfigDir,
  fileTools: OPENCODE_FILE_TOOLS,
  extraToolInputKeys: EXTRA_TOOL_INPUT_KEYS,
  /**
   * Core hands the loader a directory as `agentDir`; for opencode that must be the DATA dir (where
   * `auth.json` is), not the config dir. The plugin wires an env-aware closure (13-06) so
   * `OPENCODE_AUTH_CONTENT` is honoured; this default reads the file only.
   */
  readAuth(dataDir, modelProvider) {
    return readOpencodeAuthSummary(dataDir, modelProvider, {});
  }
});

// packages/opencode/src/verdicts.ts
var APPROVAL_PREFIX = "Unbound policy requires approval for this action";
var APPROVAL_TAIL = "opencode cannot show an approval prompt, so it was not run. Do not retry it; ask your Unbound admin to approve it.";
function approvalMessage(reason) {
  try {
    const clean = sanitizeReason(reason)?.trim();
    if (clean === void 0 || clean === "") return `${APPROVAL_PREFIX}. ${APPROVAL_TAIL}`;
    const end = /[.!?]$/.test(clean) ? "" : ".";
    return `${APPROVAL_PREFIX}: ${clean}${end} ${APPROVAL_TAIL}`;
  } catch {
    return `${APPROVAL_PREFIX}. ${APPROVAL_TAIL}`;
  }
}
function blockingMessage(verdict) {
  try {
    if (verdict === null || typeof verdict !== "object") return void 0;
    switch (verdict.kind) {
      case "deny":
      case "unavailable":
        return verdictMessage(verdict);
      case "confirm":
        return approvalMessage(verdict.reason);
      default:
        return void 0;
    }
  } catch {
    return void 0;
  }
}
var RANK = Object.freeze({
  deny: 4,
  unavailable: 3,
  confirm: 2,
  allow: 1,
  skip: 0
});
var NOTHING = Object.freeze({ kind: "skip", why: "nothing-evaluable" });
function strictest(list) {
  try {
    if (!Array.isArray(list)) return NOTHING;
    let best;
    let bestRank = -1;
    for (const verdict of list) {
      const kind = verdict?.kind;
      const rank = typeof kind === "string" && Object.hasOwn(RANK, kind) ? RANK[kind] : void 0;
      if (rank === void 0) continue;
      if (rank > bestRank) {
        best = verdict;
        bestRank = rank;
      }
    }
    return best ?? NOTHING;
  } catch {
    return NOTHING;
  }
}

// packages/opencode/src/before.ts
var APPLY_PATCH_TOOL = "apply_patch";
var MAX_TIMER_MS2 = 2147483647;
var PATCH_TOO_LARGE_REASON = `patch too large to verify: it names more than ${MAX_PATCH_TARGETS} files, so some of them could not be checked. Split it into smaller patches.`;
function readField3(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function readString(value, key) {
  const field = readField3(value, key);
  return typeof field === "string" ? field : "";
}
function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function fanOutDeadlineMs(raw) {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return Math.min(raw, MAX_TIMER_MS2);
  return PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS;
}
async function fanOut(items, limit, fn, deps) {
  const results = [];
  let next = 0;
  let expired = false;
  const worker = async () => {
    while (!expired && next < items.length) {
      const index = next;
      next += 1;
      const verdict2 = await fn(items[index]).catch(() => ({ kind: "allow" }));
      if (!expired) results.push(verdict2);
    }
  };
  const deadlineMs = fanOutDeadlineMs(deps.deadlineMs);
  let timer;
  const timedOut = new Promise((resolve3) => {
    timer = setTimeout(() => resolve3("timed-out"), deadlineMs);
  });
  const workers = [];
  for (let i = 0; i < Math.max(1, Math.min(limit, items.length)); i += 1) workers.push(worker());
  const done = Promise.all(workers).then(() => "done", () => "done");
  const raced = await Promise.race([done, timedOut]);
  if (timer !== void 0) clearTimeout(timer);
  if (raced === "done") return strictest(results);
  expired = true;
  const blocked = deps.failureAction() === "block";
  const rest = blocked ? { kind: "unavailable" } : { kind: "allow" };
  noteSafe(
    () => deps.telemetry?.reportBypass({
      errorClass: EVALUATE_DEADLINE_ERROR_CLASS,
      toolName: deps.label,
      elapsedMs: deadlineMs,
      blocked
    })
  );
  const verdict = strictest([...results, rest]);
  noteSafe(
    () => deps.onDecision?.({
      tool_name: deps.label,
      tool_use_id: deps.callID,
      decision: verdict.kind,
      tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys)
    })
  );
  return verdict;
}
var NO_DECISION = Object.freeze({ message: void 0, kind: void 0 });
function reasonOf(verdict) {
  try {
    const reason = verdict.reason;
    return typeof reason === "string" && reason !== "" ? reason : void 0;
  } catch {
    return void 0;
  }
}
async function decideBeforeVerdict(input, output, ctx) {
  try {
    const { runtime, record } = ctx;
    runtime.markBeforeSeen(readString(input, "sessionID"), readString(input, "callID"));
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === void 0 || scope === void 0) {
      if (resolved.status === "init_error") {
        if (!record.initErrorNoticeShown) {
          record.initErrorNoticeShown = true;
          void notify2(record.client, INIT_ERROR_NOTICE, "warning");
        }
        return NO_DECISION;
      }
      const instance = runtime.instances.forDirectory(record.directory);
      if (!instance.noKeyNoticeShown) {
        instance.noKeyNoticeShown = true;
        void notify2(record.client, NO_KEY_NOTICE, "info");
      }
      return NO_DECISION;
    }
    const tool = readString(input, "tool");
    const sessionID = readString(input, "sessionID");
    const callID = readString(input, "callID");
    const rawArgs = readField3(output, "args");
    const args = isPlainObject(rawArgs) ? rawArgs : {};
    const directory = record.directory;
    if (tool === TASK_TOOL) {
      if (runtime.recordingActive()) {
        noteSafe(
          () => runtime.turnFor(sessionID).recordToolCall(
            {
              tool_name: TASK_TOOL,
              tool_use_id: callID,
              decision: "audited",
              tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys)
            },
            sessionID
          )
        );
      }
      return NO_DECISION;
    }
    const builtin = BUILTIN_TOOLS.has(tool);
    const toolServerCall = tool !== "" && (!builtin || MCP_RESOURCE_TOOLS.has(tool));
    const resourceMcp = mcpResourceTarget(tool, args);
    const candidates = resourceMcp !== void 0 || builtin || tool === "" ? [] : mcpCandidates(tool, runtime.mcpServerNamesFor(record));
    const mcp = resourceMcp ?? candidates[0];
    if (candidates.length > 1) {
      runtime.reportSignal(SIGNAL_MCP_ATTRIBUTION_AMBIGUOUS, tool, `candidates_${candidates.length}`);
    }
    if (toolServerCall) {
      const attributed = mcp !== void 0 && normaliseMcp(mcp) !== void 0;
      if (!attributed) {
        runtime.reportSignal(SIGNAL_MCP_ATTRIBUTION_MISS, tool, mcp === void 0 ? "unresolved" : "name_over_cap");
        if (mcp === void 0 && !builtin) runtime.refreshMcpNames(record);
      }
    }
    const identity = runtime.identity();
    const deadlineMs = runtime.deps.deadlineMs;
    const evalDeps = {
      checker,
      profile: OPENCODE_PROFILE,
      entrypoint: runtime.entrypoint(),
      state: scope.policy,
      now: runtime.deps.now,
      ...deadlineMs === void 0 ? {} : { deadlineMs },
      ...resolved.telemetry === void 0 ? {} : { telemetry: resolved.telemetry },
      hooks: {
        notify: (message2, level) => {
          void notify2(record.client, message2, level);
        }
      },
      // Re-checked per decision: the checker may latch the key on this very call.
      onDecision: (entry) => {
        if (runtime.recordingActive()) runtime.turnFor(sessionID).recordToolCall(entry, sessionID);
      },
      ...identity === void 0 ? {} : { accountIdentity: identity }
    };
    const model = runtime.modelFor(sessionID);
    let verdict;
    if (tool === APPLY_PATCH_TOOL) {
      const { targets, capped } = applyPatchTargets(args.patchText);
      if (capped) {
        runtime.reportSignal(SIGNAL_PATCH_TARGETS_CAPPED, tool, "blocked");
        verdict = { kind: "deny", reason: PATCH_TOO_LARGE_REASON };
        noteSafe(
          () => evalDeps.onDecision?.({
            tool_name: APPLY_PATCH_TOOL,
            tool_use_id: callID,
            decision: "deny",
            tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys)
          })
        );
        const message2 = blockingMessage(verdict);
        if (message2 !== void 0) void notify2(record.client, message2, "error");
        return { message: message2, kind: "deny", reason: PATCH_TOO_LARGE_REASON };
      }
      const deleted = applyPatchDeletedPaths(args.patchText);
      verdict = await fanOut(
        targets,
        PATCH_CONCURRENCY,
        (target) => evaluateToolCall(
          {
            toolName: APPLY_PATCH_TOOL,
            toolCallId: callID,
            command: "",
            toolInput: { filePath: target },
            cwd: directory,
            sessionId: sessionID,
            model,
            ...deleted.has(target) ? { patchOperation: "delete" } : {}
          },
          evalDeps
        ),
        {
          deadlineMs,
          failureAction: () => scope.policy.getFailureAction(),
          telemetry: resolved.telemetry,
          onDecision: evalDeps.onDecision,
          label: APPLY_PATCH_TOOL,
          callID
        }
      );
    } else if (candidates.length > 1) {
      verdict = await fanOut(
        candidates,
        PATCH_CONCURRENCY,
        (candidate) => evaluateToolCall(
          {
            toolName: tool,
            toolCallId: callID,
            command: "",
            toolInput: args,
            cwd: directory,
            sessionId: sessionID,
            model,
            mcp: candidate,
            sendUnattributed: true
          },
          evalDeps
        ),
        {
          deadlineMs,
          failureAction: () => scope.policy.getFailureAction(),
          telemetry: resolved.telemetry,
          onDecision: evalDeps.onDecision,
          label: tool,
          callID
        }
      );
    } else {
      const call = {
        toolName: tool,
        toolCallId: callID,
        command: shellCommandOf(tool, args),
        toolInput: args,
        cwd: SHELL_TOOLS.has(tool) ? shellCwdOf(args, directory) : directory,
        sessionId: sessionID,
        model,
        ...mcp === void 0 ? {} : { mcp },
        ...toolServerCall ? { sendUnattributed: true } : {}
      };
      verdict = await evaluateToolCall(call, evalDeps);
    }
    const message = blockingMessage(verdict);
    if (message === void 0) {
      runtime.rememberDigest(sessionID, callID, argsDigest(rawArgs));
      return { message: void 0, kind: verdict.kind };
    }
    if (verdict.kind === "deny") void notify2(record.client, message, "error");
    else if (verdict.kind === "confirm") void notify2(record.client, message, "warning");
    const reason = reasonOf(verdict);
    return reason === void 0 ? { message, kind: verdict.kind } : { message, kind: verdict.kind, reason };
  } catch {
    return NO_DECISION;
  }
}
async function decideBefore(input, output, ctx) {
  try {
    return (await decideBeforeVerdict(input, output, ctx)).message;
  } catch {
    return void 0;
  }
}
function toolExecuteBefore(ctx) {
  return async (input, output) => {
    const message = await decideBefore(input, output, ctx).catch(() => void 0);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}

// packages/opencode/src/prompt.ts
var MAX_PROMPT_PARTS = 256;
function readField4(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function readString2(value, key) {
  const field = readField4(value, key);
  return typeof field === "string" ? field : "";
}
function promptTextOf(parts) {
  try {
    if (!Array.isArray(parts)) return "";
    const chunks = [];
    const count = Math.min(parts.length, MAX_PROMPT_PARTS);
    for (let i = 0; i < count; i += 1) {
      const part = parts[i];
      const type = readField4(part, "type");
      if (type === "subtask") {
        const prompt = readField4(part, "prompt");
        if (typeof prompt === "string" && prompt !== "") chunks.push(prompt);
        continue;
      }
      if (type !== "text") continue;
      if (readField4(part, "synthetic") === true) continue;
      const text = readField4(part, "text");
      if (typeof text === "string" && text !== "") chunks.push(text);
    }
    return chunks.join("\n");
  } catch {
    return "";
  }
}
function modelOf(input) {
  const model = readField4(input, "model");
  const provider = readString2(model, "providerID");
  const id = readString2(model, "modelID");
  if (provider === "" || id === "") return void 0;
  return { provider, model: `${provider}/${id}` };
}
async function decidePrompt(input, output, ctx) {
  try {
    const { runtime, record } = ctx;
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === void 0 || scope === void 0) return void 0;
    const sessionID = readString2(input, "sessionID");
    const captured = modelOf(input);
    if (captured !== void 0) {
      runtime.setModel(sessionID, captured.model);
      runtime.startIdentity(captured.provider);
    }
    if (runtime.isChild(sessionID)) return void 0;
    const text = promptTextOf(readField4(output, "parts"));
    if (text.trim() === "") return void 0;
    const identity = runtime.identity();
    const deadlineMs = runtime.deps.deadlineMs;
    const evalDeps = {
      checker,
      profile: OPENCODE_PROFILE,
      entrypoint: runtime.entrypoint(),
      state: scope.policy,
      now: runtime.deps.now,
      ...deadlineMs === void 0 ? {} : { deadlineMs },
      ...resolved.telemetry === void 0 ? {} : { telemetry: resolved.telemetry },
      hooks: {
        notify: (message2, level) => {
          void notify2(record.client, message2, level);
        }
      },
      ...identity === void 0 ? {} : { accountIdentity: identity }
    };
    const verdict = await evaluatePrompt(
      {
        text,
        source: "interactive",
        cwd: record.directory,
        sessionId: sessionID,
        model: runtime.modelFor(sessionID),
        hasUI: false
      },
      evalDeps
    );
    const message = blockingMessage(verdict);
    if (message === void 0) {
      if (runtime.recordingActive()) runtime.turnFor(sessionID).recordPrompt(text, sessionID);
      return void 0;
    }
    await notify2(record.client, message, verdict.kind === "confirm" ? "warning" : "error");
    return message;
  } catch {
    return void 0;
  }
}
function chatMessage(ctx) {
  return async (input, output) => {
    const message = await decidePrompt(input, output, ctx).catch(() => void 0);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}

// packages/core/src/turnLog.ts
function shouldPostTurn(record) {
  try {
    if (record === null || typeof record !== "object") return false;
    if (typeof record.prompt === "string") return true;
    return Array.isArray(record.tool_calls) && record.tool_calls.length > 0;
  } catch {
    return false;
  }
}
var MAX_REDACT_DEPTH = 8;
function redactLeaves(value, apiKey, depth) {
  if (typeof value === "string") return redactSecrets(value, apiKey);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (depth >= MAX_REDACT_DEPTH || typeof value !== "object") return void 0;
  if (Array.isArray(value)) {
    return value.map((item) => {
      const out2 = redactLeaves(item, apiKey, depth + 1);
      return out2 === void 0 ? null : out2;
    });
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return void 0;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    const redacted = redactLeaves(item, apiKey, depth + 1);
    if (redacted !== void 0) {
      Object.defineProperty(out, key, { value: redacted, enumerable: true, writable: true, configurable: true });
    }
  }
  return out;
}
function toolInputFor(value, apiKey) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
    const redacted = redactLeaves(value, apiKey, 0);
    return redacted !== null && typeof redacted === "object" && !Array.isArray(redacted) ? redacted : {};
  } catch {
    return {};
  }
}
function capAssistantText(text, apiKey) {
  try {
    if (typeof text !== "string" || text === "") return { content: "", truncated: false };
    const capped = capCommand(redactSecrets(text, apiKey), MAX_ASSISTANT_CHARS);
    return { content: capped.command, truncated: capped.truncated };
  } catch {
    return { content: "", truncated: false };
  }
}
function toolResponseFor(record, toolUseId, apiKey) {
  const results = Array.isArray(record.results) ? record.results : [];
  const match = results.find((entry) => entry?.tool_use_id === toolUseId);
  if (match === void 0) return {};
  const bytes = typeof match.content_bytes === "number" ? match.content_bytes : 0;
  let response;
  if (match.hash_skipped === true) {
    response = { hash_skipped: true, content_bytes: bytes };
  } else if (typeof match.content_sha256 === "string") {
    response = { content_sha256: match.content_sha256, content_bytes: bytes };
  } else if (typeof match.content !== "string") {
    return {};
  } else {
    response = { content_bytes: bytes };
  }
  if (typeof match.content === "string") response.content = redactSecrets(match.content, apiKey);
  if (match.is_error === true) response.is_error = true;
  if (match.content_truncated === true) response.content_truncated = true;
  if (typeof match.content_original_chars === "number") {
    response.content_original_chars = match.content_original_chars;
  }
  if (match.content_omitted === true) response.content_omitted = true;
  return response;
}
function buildTurnLogBody(record, opts) {
  let conversationId = "";
  let prompt = "";
  let toolUse = [];
  let startedAt;
  let truncated;
  let callsTruncated;
  try {
    const safe = record === null || typeof record !== "object" ? { tool_calls: [], results: [] } : record;
    conversationId = typeof safe.session_id === "string" ? safe.session_id : "";
    prompt = typeof safe.prompt === "string" ? safe.prompt : "";
    startedAt = typeof safe.started_at === "number" && Number.isFinite(safe.started_at) ? safe.started_at : void 0;
    truncated = typeof safe.results_truncated === "number" && Number.isFinite(safe.results_truncated) && safe.results_truncated > 0 ? Math.floor(safe.results_truncated) : void 0;
    callsTruncated = typeof safe.tool_calls_truncated === "number" && Number.isFinite(safe.tool_calls_truncated) && safe.tool_calls_truncated > 0 ? Math.floor(safe.tool_calls_truncated) : void 0;
    const calls = Array.isArray(safe.tool_calls) ? safe.tool_calls : [];
    toolUse = calls.map((call) => ({
      type: TURNLOG_TOOL_USE_TYPE,
      tool_name: typeof call?.tool_name === "string" ? call.tool_name : "",
      tool_use_id: typeof call?.tool_use_id === "string" ? call.tool_use_id : "",
      // `call`-derived, and still never `event.input`-derived: what the record holds was already
      // allowlisted and capped by `auditToolInput` — header decision 2.
      tool_input: toolInputFor(call?.tool_input, opts?.apiKey),
      tool_response: toolResponseFor(
        safe,
        typeof call?.tool_use_id === "string" ? call.tool_use_id : "",
        opts?.apiKey
      )
    }));
  } catch {
  }
  const assistant = capAssistantText(opts?.assistantText, opts?.apiKey);
  const body = {
    conversation_id: conversationId,
    model: TURNLOG_MODEL,
    messages: [
      { role: "user", content: prompt },
      { role: "assistant", content: assistant.content, tool_use: toolUse }
    ],
    cwd: opts.cwd,
    requestCompleted: new Date(opts.completedAtMs).toISOString(),
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
  if (startedAt !== void 0) body.requestInitialized = new Date(startedAt).toISOString();
  if (truncated !== void 0) body.results_truncated = truncated;
  if (callsTruncated !== void 0) body.tool_calls_truncated = callsTruncated;
  if (assistant.truncated) body.assistant_truncated = true;
  return withAccountIdentity(body, opts?.accountIdentity);
}

// packages/opencode/src/record.ts
function readField5(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function readString3(value, key) {
  const field = readField5(value, key);
  return typeof field === "string" ? field : "";
}
var MAX_SCALAR_OUTPUT_CHARS = 64;
function outputParts(output) {
  try {
    if (typeof output === "string") return [{ type: "text", text: output }];
    if (typeof output === "number" || typeof output === "boolean") {
      return [{ type: "text", text: String(output).slice(0, MAX_SCALAR_OUTPUT_CHARS) }];
    }
    const content = readField5(output, "content");
    return Array.isArray(content) ? content : [];
  } catch {
    return [];
  }
}
function recordResult(ctx, sessionID, callID, tool, isError, parts) {
  try {
    const { runtime } = ctx;
    if (sessionID === "" || callID === "") return;
    if (!runtime.recordingActive()) return;
    if (!runtime.markResulted(sessionID, callID)) return;
    const hashed = hashContent(parts);
    runtime.turnFor(sessionID).recordResult({
      tool_name: tool,
      tool_use_id: callID,
      is_error: isError,
      ...hashed.content_sha256 === void 0 ? {} : { content_sha256: hashed.content_sha256 },
      content_bytes: hashed.content_bytes,
      ...hashed.hash_skipped === true ? { hash_skipped: true } : {}
    });
  } catch {
  }
}
function checkTamper(ctx, sessionID, callID, tool, args) {
  try {
    const { runtime } = ctx;
    const before = runtime.takeDigest(sessionID, callID);
    if (before === void 0) return;
    const now = argsDigest(args);
    if (now === before) return;
    runtime.reportSignal(SIGNAL_ARGS_CHANGED, tool, now === void 0 ? "digest_unavailable" : "digest_mismatch");
  } catch {
  }
}
function stashBash(sessionID, part, state, ctx) {
  try {
    const callID = readString3(part, "callID");
    const status = readField5(state, "status");
    if (status === "completed" || status === "error") {
      ctx.runtime.dropUserShell(sessionID, callID);
      return;
    }
    ctx.runtime.stashUserShell(sessionID, callID, readString3(readField5(state, "input"), "command"));
  } catch {
  }
}
function onToolPart(sessionID, part, ctx) {
  const state = readField5(part, "state");
  const tool = readString3(part, "tool");
  if (tool === "bash") stashBash(sessionID, part, state, ctx);
  if (readField5(state, "status") !== "error") return;
  const callID = readString3(part, "callID");
  const error = readField5(state, "error");
  recordResult(ctx, sessionID, callID, tool, true, [{ type: "text", text: typeof error === "string" ? error : "" }]);
}
function onTextPart(sessionID, part, ctx) {
  const { runtime } = ctx;
  if (readField5(part, "synthetic") === true) return;
  if (runtime.isChild(sessionID)) return;
  if (!runtime.recordingActive()) return;
  const messageID = readString3(part, "messageID");
  if (runtime.roleOf(sessionID, messageID) !== "assistant") return;
  const partID = readString3(part, "id");
  const text = readField5(part, "text");
  if (partID === "" || typeof text !== "string") return;
  runtime.setAssistantPart(sessionID, partID, text);
}
function onPartUpdated(properties, ctx) {
  const part = readField5(properties, "part");
  const sessionID = readString3(properties, "sessionID") || readString3(part, "sessionID");
  if (sessionID === "") return;
  switch (readField5(part, "type")) {
    case "tool":
      onToolPart(sessionID, part, ctx);
      return;
    case "text":
      onTextPart(sessionID, part, ctx);
      return;
    default:
      return;
  }
}
function sanitizeHostVersion(value) {
  return typeof value === "string" && /^[0-9A-Za-z.+-]{1,64}$/.test(value) ? value : void 0;
}
function sendHeartbeat(sessionID, info, version, ctx) {
  const { runtime, record } = ctx;
  if (!runtime.recordingActive()) return;
  const resolved = runtime.init();
  const client = resolved.client;
  const scope = resolved.scope;
  if (client === void 0 || scope === void 0) return;
  const directory = directoryKey(readField5(info, "directory")) ?? record.directory;
  const gate = runtime.instances.forDirectory(directory).heartbeatGate;
  if (!gate.shouldSend(scope.policy.getFetchedAt())) return;
  gate.markSent();
  const identity = runtime.identity();
  const body = buildHeartbeatPayload(
    {
      cwd: directory,
      sessionId: sessionID,
      model: void 0,
      clientEntrypoint: runtime.entrypoint(),
      hasUI: false,
      agentVersion: version ?? "unknown",
      ...identity === void 0 ? {} : { accountIdentity: identity }
    },
    OPENCODE_PROFILE
  );
  void Promise.resolve().then(() => client.postPretool(body)).then((result) => {
    if (!result.ok) return;
    scope.policy.recordSuccess(result.body);
    try {
      resolved.cacheSync?.(scope.policy.snapshot());
    } catch {
    }
  }).catch(() => {
  });
}
function onSessionCreated(properties, ctx) {
  const { runtime } = ctx;
  const info = readField5(properties, "info");
  const sessionID = readString3(properties, "sessionID") || readString3(info, "id");
  if (sessionID === "") return;
  runtime.setParent(sessionID, readField5(info, "parentID"));
  const version = sanitizeHostVersion(readField5(info, "version"));
  if (version !== void 0) runtime.hostVersion = version;
  if (runtime.isChild(sessionID)) return;
  sendHeartbeat(sessionID, info, version, ctx);
}
function onMessageUpdated(properties, ctx) {
  const info = readField5(properties, "info");
  const sessionID = readString3(properties, "sessionID") || readString3(info, "sessionID");
  ctx.runtime.setRole(sessionID, readString3(info, "id"), readString3(info, "role"));
}
function onSessionIdle(properties, ctx) {
  const { runtime, record } = ctx;
  const sessionID = readString3(properties, "sessionID");
  if (sessionID === "" || runtime.isChild(sessionID)) return;
  const turn = runtime.sessions.forSession(sessionID).turn.take();
  const assistantText = runtime.takeAssistantText(sessionID);
  if (!runtime.recordingActive() || !shouldPostTurn(turn)) return;
  const resolved = runtime.init();
  const client = resolved.client;
  if (client === void 0 || turn === void 0) return;
  const now = runtime.deps.now;
  const completedAtMs = now();
  const identity = runtime.identity();
  const body = buildTurnLogBody(turn, {
    cwd: record.directory,
    completedAtMs,
    assistantText,
    ...resolved.apiKey === void 0 ? {} : { apiKey: resolved.apiKey },
    ...identity === void 0 ? {} : { accountIdentity: identity }
  });
  void Promise.resolve().then(() => client.postTurnLog(body)).then((ok) => {
    if (ok) return;
    resolved.telemetry?.reportTurnLogFailure({
      errorClass: "TurnLogFailed",
      toolName: "session.idle",
      elapsedMs: now() - completedAtMs
    });
  }).catch(() => {
  });
}
function onSessionDeleted(properties, ctx) {
  const info = readField5(properties, "info");
  const sessionID = readString3(properties, "sessionID") || readString3(info, "id");
  ctx.runtime.releaseSession(sessionID);
}
function handleEvent(input, ctx) {
  try {
    const event = readField5(input, "event");
    const type = readString3(event, "type");
    const properties = readField5(event, "properties");
    switch (type) {
      case "session.created":
        onSessionCreated(properties, ctx);
        return;
      case "message.part.updated":
        onPartUpdated(properties, ctx);
        return;
      case "message.updated":
        onMessageUpdated(properties, ctx);
        return;
      case "session.idle":
        onSessionIdle(properties, ctx);
        return;
      case "session.deleted":
        onSessionDeleted(properties, ctx);
        return;
      default:
        return;
    }
  } catch {
  }
}
function eventHandler(ctx) {
  return async (input) => {
    try {
      handleEvent(input, ctx);
    } catch {
    }
  };
}
function toolExecuteAfter(ctx) {
  return async (input, output) => {
    try {
      const tool = readString3(input, "tool");
      const sessionID = readString3(input, "sessionID");
      const callID = readString3(input, "callID");
      recordResult(ctx, sessionID, callID, tool, false, outputParts(readField5(output, "output")));
      checkTamper(ctx, sessionID, callID, tool, readField5(input, "args"));
    } catch {
    }
  };
}

// packages/opencode/src/userShell.ts
import { isAbsolute as isAbsolute6 } from "node:path";
function readString4(value, key) {
  try {
    if (value === null || typeof value !== "object") return "";
    const field = value[key];
    return typeof field === "string" ? field : "";
  } catch {
    return "";
  }
}
async function decideUserShell(input, ctx) {
  try {
    const { runtime } = ctx;
    const sessionID = readString4(input, "sessionID");
    const callID = readString4(input, "callID");
    if (sessionID === "" || callID === "") return void 0;
    if (runtime.beforeSeen(sessionID, callID)) return void 0;
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === void 0 || scope === void 0) return void 0;
    const command = runtime.takeUserShell(sessionID, callID);
    if (command === void 0) {
      runtime.reportSignal(SIGNAL_USER_SHELL_UNCHECKED, "bash", "no_part");
      return void 0;
    }
    return await checkUserCommand(command, readString4(input, "cwd"), sessionID, callID, ctx);
  } catch {
    return void 0;
  }
}
var NO_USER_DECISION = Object.freeze({ message: void 0, kind: void 0 });
async function checkUserCommand(command, cwdRaw, sessionID, callID, ctx) {
  try {
    return (await checkUserCommandVerdict(command, cwdRaw, sessionID, callID, ctx)).message;
  } catch {
    return void 0;
  }
}
async function checkUserCommandVerdict(command, cwdRaw, sessionID, callID, ctx) {
  try {
    const { runtime, record } = ctx;
    if (typeof command !== "string" || command === "") return NO_USER_DECISION;
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === void 0 || scope === void 0) return NO_USER_DECISION;
    const cwd = typeof cwdRaw === "string" && cwdRaw !== "" && isAbsolute6(cwdRaw) ? cwdRaw : record.directory;
    const identity = runtime.identity();
    const deadlineMs = runtime.deps.deadlineMs;
    const evalDeps = {
      checker,
      profile: OPENCODE_PROFILE,
      entrypoint: runtime.entrypoint(),
      state: scope.policy,
      now: runtime.deps.now,
      ...deadlineMs === void 0 ? {} : { deadlineMs },
      ...resolved.telemetry === void 0 ? {} : { telemetry: resolved.telemetry },
      hooks: {
        notify: (message2, level) => {
          void notify2(record.client, message2, level);
        }
      },
      onDecision: (entry) => {
        if (sessionID !== "" && runtime.recordingActive()) runtime.turnFor(sessionID).recordToolCall(entry, sessionID);
      },
      ...identity === void 0 ? {} : { accountIdentity: identity }
    };
    const verdict = await evaluateToolCall(
      {
        toolName: "bash",
        toolCallId: USER_BASH_ID_PREFIX + callID,
        command,
        toolInput: {},
        cwd,
        sessionId: sessionID,
        model: sessionID === "" ? void 0 : runtime.modelFor(sessionID)
      },
      evalDeps
    );
    const message = blockingMessage(verdict);
    if (message === void 0) return { message: void 0, kind: verdict.kind };
    await notify2(record.client, message, verdict.kind === "confirm" ? "warning" : "error");
    return { message, kind: verdict.kind };
  } catch {
    return NO_USER_DECISION;
  }
}
function shellEnv(ctx) {
  return async (input, _output) => {
    const message = await decideUserShell(input, ctx).catch(() => void 0);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}

// packages/opencode/src/plugin.ts
var BUILD_TOKEN = true ? "ebb7fbe027f819b8f084c53837a58d1b" : "source";
function isBuildToken(value) {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}
function createModuleToken(buildToken = BUILD_TOKEN) {
  return Object.freeze({ module: SENTINEL_KEY, build: buildToken });
}
var MODULE_TOKEN = createModuleToken();
var MAX_MCP_SERVER_NAMES = 1024;
var MCP_REFRESH_INTERVAL_MS = 1e4;
var MCP_REFRESH_TIMEOUT_MS = 2e3;
var MAX_DIGESTS_PER_SESSION = 256;
var MAX_PARENT_DEPTH = 8;
var MAX_MODEL_CHARS = 256;
var MAX_IDS_PER_SESSION = 512;
var MAX_MESSAGES_PER_SESSION = 256;
var MAX_ASSISTANT_PARTS = 32;
var MAX_SHELL_STASH_PER_SESSION = 32;
var INIT_RETRY_MS = 5e3;
var NO_KEY_RETRY_MS = 3e4;
var NO_KEY = Object.freeze({
  status: "no_key",
  apiKey: void 0,
  baseUrl: void 0,
  scope: void 0,
  client: void 0,
  checker: void 0,
  telemetry: void 0,
  signals: void 0,
  cacheSync: void 0
});
var INIT_ERROR = Object.freeze({
  status: "init_error",
  apiKey: void 0,
  baseUrl: void 0,
  scope: void 0,
  client: void 0,
  checker: void 0,
  telemetry: void 0,
  signals: void 0,
  cacheSync: void 0
});
function safeHomeDir() {
  try {
    return homedir();
  } catch {
    return "";
  }
}
function mcpServerNamesOf(cfg) {
  try {
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) return [];
    const mcp = cfg.mcp;
    if (mcp === null || typeof mcp !== "object" || Array.isArray(mcp)) return [];
    const names = [];
    for (const key of Object.keys(mcp)) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (typeof key === "string" && key !== "") names.push(key);
    }
    return names;
  } catch {
    return [];
  }
}
function mcpServerNamesFromList(list) {
  try {
    const names = [];
    for (const name of list) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (typeof name === "string" && name !== "" && !names.includes(name)) names.push(name);
    }
    return names;
  } catch {
    return [];
  }
}
function liveMcpNamesOf(answer) {
  try {
    if (answer === null || typeof answer !== "object") return void 0;
    const data = answer.data;
    if (data === null || typeof data !== "object" || Array.isArray(data)) return void 0;
    const names = [];
    for (const key of Object.keys(data)) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (key !== "") names.push(key);
    }
    return names;
  } catch {
    return void 0;
  }
}
function later(fn) {
  try {
    const timer = setTimeout(() => {
      try {
        fn();
      } catch {
      }
    }, 0);
    timer.unref?.();
  } catch {
  }
}
function freshRecord(directory) {
  return {
    directory,
    client: void 0,
    mcpServerNames: [],
    liveMcpServerNames: [],
    mcpRefreshedAt: void 0,
    initErrorNoticeShown: false,
    generation: 0
  };
}
function freshExtras() {
  return {
    resulted: /* @__PURE__ */ new Set(),
    roles: /* @__PURE__ */ new Map(),
    assistant: /* @__PURE__ */ new Map(),
    before: /* @__PURE__ */ new Set(),
    shell: /* @__PURE__ */ new Map()
  };
}
function boundedSet(map, key, value, max) {
  if (!map.has(key)) {
    while (map.size >= max) {
      const oldest = map.keys().next().value;
      if (oldest === void 0) break;
      map.delete(oldest);
    }
  }
  map.set(key, value);
}
function keepText(text) {
  if (text.length <= MAX_ASSISTANT_CHARS * 2) return text;
  return text.slice(0, MAX_ASSISTANT_CHARS) + text.slice(text.length - MAX_ASSISTANT_CHARS);
}
function boundedAdd(set, id, max) {
  set.add(id);
  while (set.size > max) {
    const oldest = set.values().next().value;
    if (oldest === void 0) break;
    set.delete(oldest);
  }
}
function rollUp(store, root) {
  return {
    startTurn: (_sessionId, now) => store.startTurn(root, now),
    reset: () => void 0,
    recordPrompt: (text, _sessionId, now) => store.recordPrompt(text, root, now),
    recordToolCall: (entry, _sessionId, now) => store.recordToolCall(entry, root, now),
    recordResult: (entry) => store.recordResult(entry),
    currentPrompt: () => store.currentPrompt(root),
    take: () => store.take(),
    isEmpty: () => store.isEmpty(),
    snapshot: () => store.snapshot()
  };
}
function createRuntime(overrides = {}) {
  const source = overrides ?? {};
  const deps = Object.freeze({
    scopes: source.scopes ?? createScopedStates(),
    now: typeof source.now === "function" ? source.now : Date.now,
    ...source.makeChecker === void 0 ? {} : { makeChecker: source.makeChecker },
    ...source.timeouts === void 0 ? {} : { timeouts: source.timeouts },
    ...source.deadlineMs === void 0 ? {} : { deadlineMs: source.deadlineMs },
    ...source.signalIntervalMs === void 0 ? {} : { signalIntervalMs: source.signalIntervalMs },
    sentinelKey: typeof source.sentinelKey === "symbol" ? source.sentinelKey : Symbol.for(SENTINEL_KEY),
    moduleToken: source.moduleToken ?? MODULE_TOKEN,
    buildToken: typeof source.buildToken === "string" && source.buildToken !== "" ? source.buildToken : BUILD_TOKEN
  });
  const breakers = createBreakerRegistry({ now: deps.now });
  const sessions = createSessionStates();
  const instances = createInstanceStates({ now: deps.now });
  const records = createKeyedState({
    max: MAX_TRACKED_INSTANCES,
    normalizeKey: directoryKey,
    create: (directory) => freshRecord(directory),
    fallback: () => freshRecord("")
  });
  const extras = createKeyedState({
    max: MAX_TRACKED_SESSIONS,
    create: () => freshExtras(),
    fallback: () => freshExtras()
  });
  const digests = createKeyedState({
    max: MAX_TRACKED_SESSIONS,
    create: () => /* @__PURE__ */ new Map(),
    fallback: () => /* @__PURE__ */ new Map()
  });
  let resolved;
  let retryAt = 0;
  let resolveCount = 0;
  let identityLoader;
  function loaderOf() {
    if (identityLoader === void 0) {
      const env = source.env ?? process.env;
      const homeDir = "homeDir" in source && typeof source.homeDir === "string" ? source.homeDir : safeHomeDir();
      identityLoader = createAccountIdentityLoader({
        ...source.identity ?? {},
        agentDir: resolveOpencodeDataDir(env, homeDir),
        readAuth: typeof source.readAuth === "function" ? source.readAuth : (dataDir, provider) => readOpencodeAuthSummary(dataDir, provider, env)
      });
    }
    return identityLoader;
  }
  const reportedOnce = /* @__PURE__ */ new Set();
  function resolveNow(progress) {
    const env = source.env ?? process.env;
    const homeDir = "homeDir" in source && typeof source.homeDir === "string" ? source.homeDir : safeHomeDir();
    const apiKey = resolveApiKey(env, homeDir, OPENCODE_PROFILE);
    if (apiKey === void 0) return NO_KEY;
    progress.apiKey = apiKey;
    const baseUrl = resolveGatewayUrl(env, homeDir);
    progress.baseUrl = baseUrl;
    const scope = deps.scopes.forScope(baseUrl, apiKey);
    const fingerprint = keyFingerprint(apiKey);
    const cachePath = resolveCachePath(env, homeDir, OPENCODE_PROFILE);
    try {
      if (cachePath !== void 0) {
        const onDisk = readCache(cachePath, { gatewayUrl: baseUrl, fingerprint });
        if (onDisk !== void 0) scope.policy.hydrate(onDisk);
      }
    } catch {
    }
    const cacheSync = cachePath === void 0 ? void 0 : (snapshot) => {
      void writeCache(cachePath, { ...snapshot, gateway_url: baseUrl, key_fingerprint: fingerprint });
    };
    const client = createApiClient({
      baseUrl,
      apiKey,
      profile: OPENCODE_PROFILE,
      ...deps.timeouts?.pretoolMs === void 0 ? {} : { timeoutMs: deps.timeouts.pretoolMs },
      ...deps.timeouts?.errorsMs === void 0 ? {} : { errorsTimeoutMs: deps.timeouts.errorsMs },
      ...deps.timeouts?.turnLogMs === void 0 ? {} : { turnLogTimeoutMs: deps.timeouts.turnLogMs }
    });
    const isInactive = () => scope.key.isInactive();
    const telemetry = createTelemetry({ client, profile: OPENCODE_PROFILE, apiKey, isInactive, now: deps.now });
    const signals = createSignalReporter({
      client,
      profile: OPENCODE_PROFILE,
      apiKey,
      isInactive,
      now: deps.now,
      ...deps.signalIntervalMs === void 0 ? {} : { intervalMs: deps.signalIntervalMs }
    });
    const checker = deps.makeChecker !== void 0 ? deps.makeChecker(apiKey, baseUrl) : createPolicyChecker({
      client,
      state: scope.policy,
      telemetry,
      breaker: breakers.forUrl(baseUrl),
      keyState: scope.key,
      onSync: cacheSync,
      now: deps.now
    });
    return { status: "active", apiKey, baseUrl, scope, client, checker, telemetry, signals, cacheSync };
  }
  let initFaultReported = false;
  function reportInitFault(progress) {
    if (initFaultReported) return;
    initFaultReported = true;
    const { apiKey, baseUrl } = progress;
    if (apiKey === void 0 || baseUrl === void 0) return;
    later(() => {
      const client = createApiClient({
        baseUrl,
        apiKey,
        profile: OPENCODE_PROFILE,
        ...deps.timeouts?.errorsMs === void 0 ? {} : { errorsTimeoutMs: deps.timeouts.errorsMs }
      });
      createSignalReporter({ client, profile: OPENCODE_PROFILE, apiKey, now: deps.now }).report(SIGNAL_INIT_DEGRADED, {
        toolName: "init",
        detail: "resolve_fault"
      });
    });
  }
  function nowSafe() {
    try {
      const value = deps.now();
      return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
    } catch {
      return Date.now();
    }
  }
  const runtime = {
    deps,
    sessions,
    instances,
    hostVersion: void 0,
    init() {
      const now = nowSafe();
      if (resolved !== void 0 && (resolved.status === "active" || now < retryAt)) return resolved;
      resolveCount += 1;
      const progress = {};
      try {
        resolved = resolveNow(progress);
        if (resolved.status !== "active") retryAt = now + NO_KEY_RETRY_MS;
      } catch {
        resolved = INIT_ERROR;
        retryAt = now + INIT_RETRY_MS;
        try {
          reportInitFault(progress);
        } catch {
        }
      }
      return resolved;
    },
    entrypoint() {
      const version = runtime.hostVersion;
      return typeof version === "string" && version !== "" ? ENTRYPOINT_PREFIX + version : UNKNOWN_ENTRYPOINT;
    },
    recordingActive() {
      try {
        const r = runtime.init();
        return r.apiKey !== void 0 && r.client !== void 0 && r.scope?.key.isInactive() === false;
      } catch {
        return false;
      }
    },
    reportSignal(category, toolName, detail) {
      try {
        runtime.init().signals?.report(category, detail === void 0 ? { toolName } : { toolName, detail });
      } catch {
      }
    },
    reportOnce(category, toolName, detail) {
      try {
        if (reportedOnce.has(category)) return;
        const signals = runtime.init().signals;
        if (signals === void 0) return;
        reportedOnce.add(category);
        signals.report(category, detail === void 0 ? { toolName } : { toolName, detail });
      } catch {
      }
    },
    turnFor(sessionID) {
      const root = runtime.rootOf(sessionID);
      const store = sessions.forSession(root).turn;
      return root === sessionID ? store : rollUp(store, root);
    },
    setModel(sessionID, model) {
      try {
        if (sessionID === "" || typeof model !== "string" || model === "" || model.length > MAX_MODEL_CHARS) return;
        extras.get(sessionID).model = model;
      } catch {
      }
    },
    modelFor(sessionID) {
      try {
        const own = extras.peek(sessionID)?.model;
        if (own !== void 0) return own;
        const root = runtime.rootOf(sessionID);
        return root === sessionID ? void 0 : extras.peek(root)?.model;
      } catch {
        return void 0;
      }
    },
    startIdentity(provider) {
      try {
        if (runtime.init().apiKey === void 0) return;
        void loaderOf().start(typeof provider === "string" && provider !== "" ? provider : void 0).catch(() => void 0);
      } catch {
      }
    },
    identity() {
      try {
        return identityLoader?.current();
      } catch {
        return void 0;
      }
    },
    setParent(sessionID, parentID) {
      try {
        if (sessionID === "") return;
        if (typeof parentID !== "string" || parentID === "" || parentID === sessionID) return;
        extras.get(sessionID).parent = parentID;
      } catch {
      }
    },
    isChild(sessionID) {
      try {
        const parent = extras.peek(sessionID)?.parent;
        return typeof parent === "string" && parent !== "";
      } catch {
        return false;
      }
    },
    rootOf(sessionID) {
      try {
        let current = sessionID;
        const seen = /* @__PURE__ */ new Set([current]);
        for (let depth = 0; depth < MAX_PARENT_DEPTH; depth += 1) {
          const parent = extras.peek(current)?.parent;
          if (typeof parent !== "string" || parent === "" || seen.has(parent)) break;
          seen.add(parent);
          current = parent;
        }
        return current;
      } catch {
        return sessionID;
      }
    },
    rememberDigest(sessionID, callID, digest) {
      try {
        if (sessionID === "" || callID === "") return;
        const map = digests.get(sessionID);
        map.delete(callID);
        if (digest === void 0) return;
        map.set(callID, digest);
        while (map.size > MAX_DIGESTS_PER_SESSION) {
          const oldest = map.keys().next().value;
          if (oldest === void 0) break;
          map.delete(oldest);
        }
      } catch {
      }
    },
    takeDigest(sessionID, callID) {
      try {
        const map = digests.peek(sessionID);
        const digest = map?.get(callID);
        map?.delete(callID);
        return digest;
      } catch {
        return void 0;
      }
    },
    setRole(sessionID, messageID, role) {
      try {
        if (sessionID === "" || messageID === "" || typeof role !== "string" || role === "") return;
        boundedSet(extras.get(sessionID).roles, messageID, role, MAX_MESSAGES_PER_SESSION);
      } catch {
      }
    },
    roleOf(sessionID, messageID) {
      try {
        return extras.peek(sessionID)?.roles.get(messageID);
      } catch {
        return void 0;
      }
    },
    setAssistantPart(sessionID, partID, text) {
      try {
        if (sessionID === "" || partID === "" || typeof text !== "string") return;
        boundedSet(extras.get(sessionID).assistant, partID, keepText(text), MAX_ASSISTANT_PARTS);
      } catch {
      }
    },
    takeAssistantText(sessionID) {
      try {
        const kept = extras.peek(sessionID);
        if (kept === void 0) return "";
        const text = [...kept.assistant.values()].filter((t) => t !== "").join("\n");
        kept.assistant.clear();
        kept.roles.clear();
        return text;
      } catch {
        return "";
      }
    },
    releaseSession(sessionID) {
      try {
        if (sessionID === "") return;
        sessions.release(sessionID);
        extras.release(sessionID);
        digests.release(sessionID);
      } catch {
      }
    },
    markBeforeSeen(sessionID, callID) {
      try {
        if (sessionID === "" || callID === "") return;
        boundedAdd(extras.get(sessionID).before, callID, MAX_IDS_PER_SESSION);
        extras.peek(sessionID)?.shell.delete(callID);
      } catch {
      }
    },
    beforeSeen(sessionID, callID) {
      try {
        return extras.peek(sessionID)?.before.has(callID) === true;
      } catch {
        return false;
      }
    },
    stashUserShell(sessionID, callID, command) {
      try {
        if (sessionID === "" || callID === "" || typeof command !== "string" || command === "") return;
        const kept = extras.get(sessionID);
        if (kept.before.has(callID)) return;
        boundedSet(kept.shell, callID, capCommand(command).command, MAX_SHELL_STASH_PER_SESSION);
      } catch {
      }
    },
    takeUserShell(sessionID, callID) {
      try {
        const map = extras.peek(sessionID)?.shell;
        const command = map?.get(callID);
        map?.delete(callID);
        return command;
      } catch {
        return void 0;
      }
    },
    dropUserShell(sessionID, callID) {
      try {
        extras.peek(sessionID)?.shell.delete(callID);
      } catch {
      }
    },
    mcpServerNamesFor(record) {
      try {
        const names = [...record.mcpServerNames];
        const seen = new Set(names);
        for (const name of record.liveMcpServerNames) {
          if (names.length >= MAX_MCP_SERVER_NAMES) break;
          if (!seen.has(name)) {
            seen.add(name);
            names.push(name);
          }
        }
        return names;
      } catch {
        return [];
      }
    },
    refreshMcpNames(record) {
      try {
        const now = deps.now();
        const last = record.mcpRefreshedAt;
        if (last !== void 0 && now - last < MCP_REFRESH_INTERVAL_MS) return;
        record.mcpRefreshedAt = now;
        const mcp = record.client?.mcp;
        const status = mcp?.status;
        if (typeof status !== "function") return;
        const pending = Promise.resolve(status.call(mcp));
        let timer;
        const timeout = new Promise((resolve3) => {
          timer = setTimeout(() => resolve3(void 0), MCP_REFRESH_TIMEOUT_MS);
          timer.unref?.();
        });
        void Promise.race([pending, timeout]).then((answer) => {
          const names = liveMcpNamesOf(answer);
          if (names !== void 0) record.liveMcpServerNames = names;
        }).catch(() => void 0).finally(() => {
          if (timer !== void 0) clearTimeout(timer);
        });
      } catch {
      }
    },
    markResulted(sessionID, callID) {
      try {
        if (sessionID === "" || callID === "") return false;
        const seen = extras.get(sessionID).resulted;
        if (seen.has(callID)) return false;
        boundedAdd(seen, callID, MAX_IDS_PER_SESSION);
        return true;
      } catch {
        return false;
      }
    }
  };
  return {
    runtime,
    recordFor(directory, client, mcpServerNames) {
      const record = records.get(directory);
      record.client = client;
      if (Array.isArray(mcpServerNames)) record.mcpServerNames = mcpServerNamesFromList(mcpServerNames);
      return record;
    },
    peekRecord: (directory) => records.peek(directory),
    releaseRecord: (directory) => records.release(directory),
    resolveCount: () => resolveCount,
    hasChecker: () => resolved?.checker !== void 0
  };
}
function createServerPlugin(overrides = {}) {
  const handle = createRuntime(overrides);
  const { runtime } = handle;
  const deps = runtime.deps;
  function degradedHooks() {
    later(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, "server", "factory_fault"));
    return {
      "tool.execute.before": async () => {
        try {
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "tool.execute.before", "factory_fault");
        } catch {
        }
        return void 0;
      },
      event: async () => {
        try {
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "event", "factory_fault");
        } catch {
        }
      }
    };
  }
  function fullHooks(record, generation) {
    return {
      // The enforcement path. The handler raises only through `block.ts`, and only on a verdict.
      "tool.execute.before": toolExecuteBefore({ runtime, record }),
      // The success-path audit and the args tamper check. Never raises.
      "tool.execute.after": toolExecuteAfter({ runtime, record }),
      // The prompt check (V1-5 GO). Raises only through `block.ts`, and only on a verdict.
      "chat.message": chatMessage({ runtime, record }),
      // User `!cmd` (V1-7 GO). Raises only through `block.ts`, only on a verdict, and never for a
      // call that passed `tool.execute.before` (model bash is not checked twice).
      "shell.env": shellEnv({ runtime, record }),
      // The bus. Never rejects (V1-4): every branch is guarded and nothing is awaited.
      event: eventHandler({ runtime, record }),
      // Called with the live merged config once per instance. Read-only (Pitfall 16): the object is
      // shared with every other plugin, so only its MCP server NAMES are copied out.
      config: async (cfg) => {
        try {
          record.mcpServerNames = mcpServerNamesOf(cfg);
        } catch {
        }
        try {
          runtime.init();
        } catch {
        }
      },
      // Instance teardown: drop this directory's state. A pending turn is never posted from here.
      // Only the LATEST hook set of the directory releases it (13-REVIEW WR-05): a late dispose of an
      // instance that a newer `server()` call superseded, or of a record already replaced after an
      // earlier release, must not drop the live instance's record, heartbeat gate or no-key latch.
      dispose: async () => {
        try {
          if (record.directory !== "" && record.generation === generation && handle.peekRecord(record.directory) === record) {
            runtime.instances.release(record.directory);
            handle.releaseRecord(record.directory);
          }
        } catch {
        }
      }
    };
  }
  function claimSentinel() {
    try {
      Object.defineProperty(globalThis, deps.sentinelKey, {
        value: deps.moduleToken,
        writable: false,
        configurable: false,
        enumerable: false
      });
      return true;
    } catch {
      return false;
    }
  }
  function sentinelHolder() {
    try {
      const desc = Object.getOwnPropertyDescriptor(globalThis, deps.sentinelKey);
      if (desc === void 0) return "free";
      if (!("value" in desc)) return { foreign: "accessor" };
      const holder = desc.value;
      if (holder === deps.moduleToken) return "mine";
      if (holder === null || typeof holder !== "object") return { foreign: "foreign_value" };
      const own = (key) => {
        const d = Object.getOwnPropertyDescriptor(holder, key);
        return d !== void 0 && "value" in d ? d.value : void 0;
      };
      if (own("module") !== SENTINEL_KEY) return { foreign: "foreign_value" };
      const wellFormed = desc.writable === false && desc.configurable === false && Object.isFrozen(holder);
      if (own("build") !== deps.buildToken) {
        return wellFormed && isBuildToken(own("build")) ? "other_build" : { foreign: "other_build" };
      }
      if (!wellFormed) return { foreign: "forged_holder" };
      return "duplicate";
    } catch {
      return { foreign: "unreadable" };
    }
  }
  const factory = (input, _options) => {
    try {
      const holder = sentinelHolder();
      if (holder === "duplicate") {
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, "server", "second_copy"));
        return Promise.resolve({});
      }
      if (holder === "free") {
        claimSentinel();
      } else if (holder === "other_build") {
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, "server", "other_build"));
      } else if (holder !== "mine") {
        let configurable = false;
        try {
          configurable = Object.getOwnPropertyDescriptor(globalThis, deps.sentinelKey)?.configurable === true;
        } catch {
        }
        if (configurable) claimSentinel();
        const detail = holder.foreign;
        later(() => runtime.reportOnce(SIGNAL_SENTINEL_TAMPERED, "server", detail));
      }
      const host = input !== null && typeof input === "object" ? input : {};
      const directory = host.directory;
      const client = host.client;
      const record = handle.recordFor(directory, client);
      record.generation += 1;
      return Promise.resolve(fullHooks(record, record.generation));
    } catch {
      return Promise.resolve(degradedHooks());
    }
  };
  const inspector = {
    resolveCount: () => handle.resolveCount(),
    hasChecker: () => handle.hasChecker(),
    instance(dir) {
      const record = handle.peekRecord(dir);
      return record === void 0 ? void 0 : { directory: record.directory, mcpServerNames: [...record.mcpServerNames] };
    },
    turn: (sessionID) => runtime.sessions.forSession(sessionID).turn.snapshot(),
    runtime: () => runtime
  };
  Object.defineProperty(factory, "inspect", { value: inspector, enumerable: false });
  return factory;
}

// packages/opencode/src/v2Enforce.ts
import { isAbsolute as isAbsolute7, resolve as resolve2 } from "node:path";
var V2_SHELL_TOOL = "shell";
var V2_SUBAGENT_TOOL = "subagent";
var V2_CODE_MODE_TOOL = "execute";
var V2_BUILTIN_TOOLS = /* @__PURE__ */ new Set([
  "edit",
  "glob",
  "grep",
  "question",
  "read",
  V2_SHELL_TOOL,
  "skill",
  V2_SUBAGENT_TOOL,
  "webfetch",
  "websearch",
  "write",
  V2_CODE_MODE_TOOL
]);
var MAX_PENDING_CALLS = 1024;
var SESSION_GET_TIMEOUT_MS = 1e3;
var MCP_LIST_TIMEOUT_MS = 1e3;
var MCP_LIST_INTERVAL_MS = 1e4;
var MAX_WARNED_SESSIONS = 1024;
var MAX_PENDING_SHELLS = 256;
var MAX_INTERRUPTED_SESSIONS = 1024;
var PENDING_SHELL_TTL_MS = 5e3;
var MAX_SESSION_DIRS = 1024;
var MAX_SEEN_EVENTS = 4096;
var MAX_CODE_MODE_CALLS = 1024;
var MAX_OPEN_INNER_CALLS = 256;
function openCodeModeCall(scope, sessionID, callID) {
  try {
    if (sessionID === "" || callID === "") return callID;
    const key = `${sessionID}\0${callID}`;
    const entry = scope.codeMode.get(key) ?? { next: 0, open: [], overlapped: false };
    scope.codeMode.delete(key);
    scope.codeMode.set(key, entry);
    while (scope.codeMode.size > MAX_CODE_MODE_CALLS) {
      const oldest = scope.codeMode.keys().next().value;
      if (oldest === void 0) break;
      scope.codeMode.delete(oldest);
    }
    const id = entry.next === 0 ? callID : `${callID}#${entry.next}`;
    entry.next += 1;
    entry.open.push(id);
    while (entry.open.length > MAX_OPEN_INNER_CALLS) entry.open.shift();
    if (entry.open.length > 1) entry.overlapped = true;
    return id;
  } catch {
    return callID;
  }
}
function closeCodeModeCall(scope, sessionID, callID, numbered) {
  try {
    const open = scope.codeMode.get(`${sessionID}\0${callID}`)?.open;
    const index = open?.indexOf(numbered) ?? -1;
    if (open !== void 0 && index >= 0) open.splice(index, 1);
  } catch {
  }
}
function takeCodeModeResult(scope, sessionID, callID) {
  try {
    const entry = scope.codeMode.get(`${sessionID}\0${callID}`);
    if (entry === void 0 || entry.open.length === 0) return void 0;
    const concurrent = entry.overlapped || entry.open.length > 1;
    const numbered = entry.open.shift();
    if (entry.open.length === 0) entry.overlapped = false;
    return numbered === void 0 ? void 0 : { callID: numbered, concurrent };
  } catch {
    return void 0;
  }
}
function noteActivity(scope) {
  try {
    scope.onActivity?.();
  } catch {
  }
}
function createV2Scope(directories = /* @__PURE__ */ new Set()) {
  return {
    modelShells: [],
    interrupted: /* @__PURE__ */ new Map(),
    directories,
    sessionDirs: /* @__PURE__ */ new Map(),
    seenEvents: /* @__PURE__ */ new Set(),
    seenHookInputs: /* @__PURE__ */ new Map(),
    evaluateWithoutSource: false,
    confirmedRoots: /* @__PURE__ */ new Set(),
    onActivity: void 0,
    codeMode: /* @__PURE__ */ new Map()
  };
}
function noteRootSession(scope, sessionID) {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    scope.confirmedRoots.delete(sessionID);
    scope.confirmedRoots.add(sessionID);
    while (scope.confirmedRoots.size > MAX_CONFIRMED_ROOTS) {
      const oldest = scope.confirmedRoots.values().next().value;
      if (oldest === void 0) break;
      scope.confirmedRoots.delete(oldest);
    }
  } catch {
  }
}
function noteSessionDirectory(scope, sessionID, directory) {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    const key = directoryKey(directory);
    if (key === void 0) return;
    scope.sessionDirs.delete(sessionID);
    scope.sessionDirs.set(sessionID, key);
    while (scope.sessionDirs.size > MAX_SESSION_DIRS) {
      const oldest = scope.sessionDirs.keys().next().value;
      if (oldest === void 0) break;
      scope.sessionDirs.delete(oldest);
    }
  } catch {
  }
}
function claimHookInput(scope, hook, input) {
  try {
    if (input === null || typeof input !== "object") return true;
    let seen = scope.seenHookInputs.get(hook);
    if (seen === void 0) {
      seen = /* @__PURE__ */ new WeakSet();
      scope.seenHookInputs.set(hook, seen);
    }
    if (seen.has(input)) return false;
    seen.add(input);
    return true;
  } catch {
    return true;
  }
}
function claimEvent(scope, ownDirectory, event) {
  try {
    const own = directoryKey(ownDirectory);
    const data = readField6(event, "data");
    const located = directoryKey(readString5(readField6(event, "location"), "directory")) ?? directoryKey(readString5(readField6(data, "location"), "directory"));
    const owner = located ?? scope.sessionDirs.get(readString5(data, "sessionID"));
    if (owner !== void 0 && owner !== own && scope.directories.has(owner)) return false;
    const id = readString5(event, "id");
    if (id === "") return true;
    if (scope.seenEvents.has(id)) return false;
    scope.seenEvents.add(id);
    while (scope.seenEvents.size > MAX_SEEN_EVENTS) {
      const oldest = scope.seenEvents.values().next().value;
      if (oldest === void 0) break;
      scope.seenEvents.delete(oldest);
    }
    return true;
  } catch {
    return true;
  }
}
function noteInterrupted(scope, sessionID, at) {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    scope.interrupted.delete(sessionID);
    scope.interrupted.set(sessionID, at);
    while (scope.interrupted.size > MAX_INTERRUPTED_SESSIONS) {
      const oldest = scope.interrupted.keys().next().value;
      if (oldest === void 0) break;
      scope.interrupted.delete(oldest);
    }
    for (let i = scope.modelShells.length - 1; i >= 0; i -= 1) {
      if (scope.modelShells[i]?.sessionID === sessionID) scope.modelShells.splice(i, 1);
    }
  } catch {
  }
}
function disposeOne(registration) {
  try {
    const dispose = readField6(registration, "dispose");
    if (typeof dispose !== "function") return;
    void Promise.resolve(dispose.call(registration)).catch(() => void 0);
  } catch {
  }
}
function createV2Registrations() {
  const kept = [];
  let disposed = false;
  return {
    track(registration) {
      try {
        void Promise.resolve(registration).then(
          (handle) => {
            if (disposed) disposeOne(handle);
            else kept.push(handle);
          },
          () => void 0
        );
      } catch {
      }
    },
    dispose() {
      disposed = true;
      for (const handle of kept.splice(0, kept.length)) disposeOne(handle);
    },
    size: () => kept.length
  };
}
function modelShellCwd(input, sessionID, directory, scope) {
  try {
    const workdir = readField6(input, "workdir");
    if (typeof workdir === "string" && workdir !== "" && isAbsolute7(workdir)) return directoryKey(workdir) ?? "";
    const base = scope.sessionDirs.get(sessionID) ?? (scope.directories.size > 1 ? void 0 : directoryKey(directory));
    if (base === void 0) return "";
    if (typeof workdir === "string" && workdir !== "") return directoryKey(resolve2(base, workdir)) ?? "";
    return base;
  } catch {
    return "";
  }
}
var APPROVAL_NATIVE_TAIL = "Approve it only if you expect it.";
var SUBAGENT_PROMPT_PREFIX = "You are a subagent spawned by another session.\n";
var MAX_CONFIRMED_ROOTS = 1024;
var PROMPT_BLOCK_TAIL = "(Unbound replaced the user's message because a policy blocked it; the original was not sent. Tell the user their message was blocked by Unbound policy and do nothing else.)";
function readField6(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function readString5(value, key) {
  const field = readField6(value, key);
  return typeof field === "string" ? field : "";
}
function v1ToolName(tool) {
  if (tool === V2_SHELL_TOOL) return "bash";
  if (tool === V2_SUBAGENT_TOOL) return "task";
  return typeof tool === "string" ? tool : "";
}
function nativeApprovalMessage(reason) {
  try {
    const clean = sanitizeReason(reason)?.trim();
    if (clean === void 0 || clean === "") return `${APPROVAL_PREFIX}. ${APPROVAL_NATIVE_TAIL}`;
    const end = /[.!?]$/.test(clean) ? "" : ".";
    return `${APPROVAL_PREFIX}: ${clean}${end} ${APPROVAL_NATIVE_TAIL}`;
  } catch {
    return `${APPROVAL_PREFIX}. ${APPROVAL_NATIVE_TAIL}`;
  }
}
function promptBlockNotice(message) {
  const text = typeof message === "string" && message !== "" ? message : "Blocked by Unbound policy.";
  return `${text}

${PROMPT_BLOCK_TAIL}`;
}
function v2HostClient(ctx, directory) {
  return {
    mcp: {
      status: async () => {
        try {
          const names = await listMcpNames(ctx, directory);
          if (names === void 0) return void 0;
          const data = {};
          for (const name of names) data[name] = true;
          return { data };
        } catch {
          return void 0;
        }
      }
    }
  };
}
async function listMcpNames(ctx, directory) {
  const scoped = directory === "" ? void 0 : await listMcpNamesWith(ctx, { location: { directory } });
  return scoped ?? await listMcpNamesWith(ctx, void 0);
}
async function listMcpNamesWith(ctx, input) {
  try {
    const mcp = ctx.mcp;
    const list = readField6(mcp, "list");
    if (typeof list !== "function") return void 0;
    const answer = await list.call(mcp, input);
    const data = readField6(answer, "data");
    if (!Array.isArray(data)) return void 0;
    const names = [];
    for (const server of data.slice(0, 1024)) {
      const name = readString5(server, "name");
      if (name !== "" && !names.includes(name)) names.push(name);
    }
    return names;
  } catch {
    return void 0;
  }
}
function bounded(promise, ms) {
  return new Promise((resolve3) => {
    let timer;
    try {
      timer = setTimeout(() => resolve3(void 0), ms);
      timer.unref?.();
    } catch {
    }
    promise.then(
      (value) => {
        if (timer !== void 0) clearTimeout(timer);
        resolve3(value);
      },
      () => {
        if (timer !== void 0) clearTimeout(timer);
        resolve3(void 0);
      }
    );
  });
}
function permissionActionOf(tool) {
  return tool === "write" ? "edit" : tool;
}
var NO_DECISION2 = Object.freeze({ message: void 0, kind: void 0 });
var NO_OUTCOME = Object.freeze({ raise: void 0, kind: void 0 });
function registerV2Enforcement(ctx, runtime, recordFor, capabilities = V2_CAPABILITIES, scope = createV2Scope(), registrations = createV2Registrations()) {
  try {
    const directory = readString5(readField6(ctx, "location"), "directory");
    const pending = /* @__PURE__ */ new Map();
    const warned = /* @__PURE__ */ new Set();
    const modelShells = scope.modelShells;
    let userShellSeq = 0;
    const nowSafe = () => {
      try {
        const value = runtime.deps.now();
        return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
      } catch {
        return Date.now();
      }
    };
    const markModelShell = (event, kind, started) => {
      try {
        if (readString5(event, "tool") !== V2_SHELL_TOOL) return;
        const input = readField6(event, "input");
        const command = readString5(input, "command");
        if (command === "") return;
        const sessionID = readString5(event, "sessionID");
        const interruptedAt = sessionID === "" ? void 0 : scope.interrupted.get(sessionID);
        if (interruptedAt !== void 0 && interruptedAt >= started) return;
        modelShells.push({
          command,
          cwd: modelShellCwd(input, sessionID, directory, scope),
          at: nowSafe(),
          sessionID,
          denied: kind === "deny" || kind === "unavailable"
        });
        while (modelShells.length > MAX_PENDING_SHELLS) modelShells.shift();
      } catch {
      }
    };
    const takeModelShell = (command, cwdRaw, timeout) => {
      try {
        const now = nowSafe();
        while (modelShells.length > 0 && now - (modelShells[0]?.at ?? now) > PENDING_SHELL_TTL_MS) modelShells.shift();
        if (timeout === 0) return false;
        const cwd = directoryKey(cwdRaw) ?? "";
        const toolSpawn = typeof timeout === "number" && Number.isFinite(timeout) && timeout > 0;
        const index = modelShells.findIndex(
          (mark) => mark.command === command && (mark.cwd === "" || cwd === "" || mark.cwd === cwd) && (!mark.denied || toolSpawn)
        );
        if (index < 0) return false;
        modelShells.splice(index, 1);
        return true;
      } catch {
        return false;
      }
    };
    const keyOf = (sessionID, callID) => `${sessionID}\0${callID}`;
    const remember2 = (key, call) => {
      pending.delete(key);
      pending.set(key, call);
      while (pending.size > MAX_PENDING_CALLS) {
        const oldest = pending.keys().next().value;
        if (oldest === void 0) break;
        pending.delete(oldest);
      }
    };
    const record = () => recordFor(directory);
    const learnMcpNames = async (tool2, rec) => {
      try {
        if (mcpCandidates(tool2, runtime.mcpServerNamesFor(rec)).length > 0) return;
        const now = runtime.deps.now();
        const last = rec.mcpRefreshedAt;
        if (last !== void 0 && now - last < MCP_LIST_INTERVAL_MS) return;
        rec.mcpRefreshedAt = now;
        const names = await bounded(listMcpNames(ctx, directory), MCP_LIST_TIMEOUT_MS);
        if (names !== void 0) rec.liveMcpServerNames = names;
      } catch {
      }
    };
    const decideToolCall = async (event) => {
      try {
        const tool2 = readString5(event, "tool");
        const sessionID = readString5(event, "sessionID");
        const callID = readString5(event, "id");
        if (tool2 === "" || tool2 === V2_CODE_MODE_TOOL) return NO_OUTCOME;
        const builtin = V2_BUILTIN_TOOLS.has(tool2);
        if (!builtin && capabilities.mcp === "none") return NO_OUTCOME;
        const rec = record();
        if (!builtin) await learnMcpNames(tool2, rec);
        const numbered = builtin ? callID : openCodeModeCall(scope, sessionID, callID);
        const decision = decideBeforeVerdict(
          { tool: v1ToolName(tool2), sessionID, callID: numbered },
          { args: readField6(event, "input") },
          { runtime, record: rec }
        ).catch(() => NO_DECISION2);
        const correlatable = sessionID !== "" && callID !== "" && !scope.evaluateWithoutSource;
        if (builtin && sessionID !== "" && callID !== "") {
          remember2(keyOf(sessionID, callID), { decision, asked: false, action: permissionActionOf(tool2) });
        }
        const { message, kind } = await decision;
        if (message === void 0) return { raise: void 0, kind };
        if (capabilities.tools === "audit") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool2, "tools");
          return { raise: void 0, kind };
        }
        if (builtin) return { raise: correlatable ? void 0 : message, kind };
        if (capabilities.mcp !== "enforce") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool2, "mcp");
          return { raise: void 0, kind };
        }
        return { raise: message, kind, numbered };
      } catch {
        return NO_OUTCOME;
      }
    };
    const applyEvaluate = async (event) => {
      try {
        const source = readField6(event, "source");
        const callID = readString5(source, "id");
        const sessionID = readString5(event, "sessionID");
        if (callID === "") {
          await applyUncorrelated(event, sessionID);
          return;
        }
        if (sessionID === "") return;
        const call = pending.get(keyOf(sessionID, callID));
        if (call === void 0) return;
        const decision = await call.decision;
        if (decision.message === void 0) return;
        if (capabilities.tools === "audit") return;
        if (readField6(event, "effect") === "deny") return;
        if (decision.kind === "confirm") {
          if (capabilities.ask === "native") {
            if (call.asked) return;
            call.asked = true;
            event.effect = "ask";
            event.message = nativeApprovalMessage(decision.reason);
            return;
          }
          if (capabilities.ask === "deny") {
            event.effect = "deny";
            event.message = decision.message;
            return;
          }
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, readString5(event, "action"), "ask");
          return;
        }
        event.effect = "deny";
        event.message = decision.message;
      } catch {
      }
    };
    const applyUncorrelated = async (event, sessionID) => {
      try {
        if (!scope.evaluateWithoutSource) {
          scope.evaluateWithoutSource = true;
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "permission.evaluate", "evaluate_no_source");
        }
        if (sessionID === "" || capabilities.tools === "audit") return;
        if (readField6(event, "effect") === "deny") return;
        const action = readString5(event, "action");
        const prefix = `${sessionID}\0`;
        const matched = [];
        for (const [key, call] of pending) {
          if (key.startsWith(prefix) && call.action === action) matched.push([key, call]);
        }
        let strictest2;
        for (const [key, call] of matched) {
          const decision = await call.decision;
          if (decision.message === void 0) continue;
          pending.delete(key);
          if (strictest2 === void 0 || strictest2.kind === "confirm" && decision.kind !== "confirm") strictest2 = decision;
        }
        if (strictest2?.message === void 0) return;
        event.effect = "deny";
        event.message = strictest2.message;
      } catch {
      }
    };
    const sessionInfo = async (sessionID) => {
      try {
        const session2 = ctx.session;
        const get = readField6(session2, "get");
        if (typeof get !== "function" || sessionID === "") return void 0;
        const answer = await bounded(
          Promise.resolve(get.call(session2, { sessionID })),
          SESSION_GET_TIMEOUT_MS
        );
        return answer !== null && typeof answer === "object" ? answer : void 0;
      } catch {
        return void 0;
      }
    };
    const handlePrompt = async (event) => {
      try {
        const sessionID = readString5(event, "sessionID");
        const prompt = readField6(event, "prompt");
        const text = readField6(prompt, "text");
        const info = await sessionInfo(sessionID);
        let root;
        if (info !== void 0) {
          runtime.setParent(sessionID, readField6(info, "parentID"));
          noteSessionDirectory(scope, sessionID, readString5(readField6(info, "location"), "directory"));
          root = !runtime.isChild(sessionID);
        } else if (runtime.isChild(sessionID)) {
          return;
        } else if (typeof text === "string" && text.startsWith(SUBAGENT_PROMPT_PREFIX)) {
          return;
        } else {
          root = sessionID !== "" && scope.confirmedRoots.has(sessionID);
        }
        const model = readField6(info, "model");
        const providerID = readString5(model, "providerID");
        const modelID = readString5(model, "id");
        const input = providerID !== "" && modelID !== "" ? { sessionID, model: { providerID, modelID } } : { sessionID };
        const output = { parts: typeof text === "string" ? [{ type: "text", text }] : [] };
        const message = await decidePrompt(input, output, { runtime, record: record() });
        if (message === void 0) return;
        if (!root) {
          runtime.reportSignal(SIGNAL_V2_NOT_ENFORCING, "prompt", "parent_unknown");
          return;
        }
        if (capabilities.prompt === "block") {
          const notice = promptBlockNotice(message);
          let replaced = false;
          try {
            const target = prompt;
            target.text = notice;
            if ("files" in target) target.files = [];
            if ("agents" in target) target.agents = [];
            if ("skills" in target) target.skills = [];
            replaced = target.text === notice;
          } catch {
            replaced = false;
          }
          if (!replaced) runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, "prompt", "prompt_mutate_failed");
          return;
        }
        if (sessionID !== "" && !warned.has(sessionID)) {
          warned.add(sessionID);
          while (warned.size > MAX_WARNED_SESSIONS) {
            const oldest = warned.values().next().value;
            if (oldest === void 0) break;
            warned.delete(oldest);
          }
          runtime.reportSignal(SIGNAL_V2_PROMPT_WARN_ONLY, "prompt", "would_block");
        }
      } catch {
      }
    };
    const decideUserShell2 = async (event) => {
      try {
        const command = readString5(event, "command");
        if (command === "" || takeModelShell(command, readString5(event, "cwd"), readField6(event, "timeout"))) return void 0;
        userShellSeq += 1;
        const callID = `v2_${nowSafe().toString(36)}_${userShellSeq}`;
        const { message, kind } = await checkUserCommandVerdict(command, readString5(event, "cwd"), "", callID, {
          runtime,
          record: record()
        });
        if (message === void 0) return void 0;
        if (kind === "unavailable") {
          runtime.reportSignal(SIGNAL_USER_SHELL_UNCHECKED, "bash", "unavailable_not_applied");
          return void 0;
        }
        if (capabilities.userShell !== "enforce") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, "bash", "user_shell");
          return void 0;
        }
        return message;
      } catch {
        return void 0;
      }
    };
    const tool = ctx.tool;
    if (tool !== void 0 && typeof tool.hook === "function") {
      registrations.track(
        tool.hook("execute.before", async (event) => {
          if (!claimHookInput(scope, "tool.execute.before", event)) return;
          noteActivity(scope);
          const started = nowSafe();
          const outcome = await decideToolCall(event).catch(() => NO_OUTCOME);
          const message = outcome.raise;
          if (typeof message === "string" && message.length > 0) {
            if (outcome.numbered !== void 0) {
              closeCodeModeCall(scope, readString5(event, "sessionID"), readString5(event, "id"), outcome.numbered);
            }
            block(message);
          }
          markModelShell(event, outcome.kind, started);
        })
      );
    }
    const permission = ctx.permission;
    if (permission !== void 0 && typeof permission.hook === "function") {
      registrations.track(
        permission.hook("evaluate", async (event) => {
          if (claimHookInput(scope, "permission.evaluate", event)) await applyEvaluate(event);
        })
      );
    }
    const session = ctx.session;
    if (session !== void 0 && typeof session.hook === "function") {
      registrations.track(
        session.hook("prompt", async (event) => {
          if (!claimHookInput(scope, "session.prompt", event)) return;
          noteActivity(scope);
          await handlePrompt(event);
        })
      );
    }
    const shell = ctx.shell;
    if (capabilities.userShell !== "none" && shell !== void 0 && typeof shell.hook === "function") {
      registrations.track(
        shell.hook("create.before", async (event) => {
          if (!claimHookInput(scope, "shell.create.before", event)) return;
          const message = await decideUserShell2(event).catch(() => void 0);
          if (typeof message === "string" && message.length > 0) block(message);
        })
      );
    }
    return true;
  } catch {
    return false;
  }
}

// packages/opencode/src/v2Record.ts
var V2_RECORDING_GAPS = Object.freeze([]);
var MAX_TRACKED_CALLS = 1024;
var PROVIDER_ID = /^[A-Za-z0-9._-]{1,64}$/;
function readField7(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function readString6(value, key) {
  const field = readField7(value, key);
  return typeof field === "string" ? field : "";
}
function v2ProviderIdentity(provider) {
  try {
    if (typeof provider !== "string" || !PROVIDER_ID.test(provider)) return void 0;
    return { provider, hasCredential: false, anthropicOAuth: false };
  } catch {
    return void 0;
  }
}
function nowOf(runtime) {
  try {
    const value = runtime.deps.now();
    return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
  } catch {
    return Date.now();
  }
}
function remember(map, key, value) {
  map.delete(key);
  map.set(key, value);
  while (map.size > MAX_TRACKED_CALLS) {
    const oldest = map.keys().next().value;
    if (oldest === void 0) break;
    map.delete(oldest);
  }
}
function modelOf2(model) {
  const provider = readString6(model, "providerID");
  const id = readString6(model, "id");
  if (provider === "" || id === "") return void 0;
  return { provider, model: `${provider}/${id}` };
}
function registerV2Recording(ctx, runtime, recordFor, scope = createV2Scope(), registrations = createV2Registrations()) {
  let controller;
  let stopped = false;
  const stop = () => {
    stopped = true;
    try {
      controller?.abort();
    } catch {
    }
  };
  try {
    const directory = readString6(readField7(ctx, "location"), "directory");
    const app = readField7(ctx, "app");
    const appVersion = sanitizeHostVersion(readField7(app, "version"));
    if (appVersion !== void 0 && runtime.hostVersion === void 0) runtime.hostVersion = appVersion;
    const toolNames = /* @__PURE__ */ new Map();
    const afterCounts = /* @__PURE__ */ new Map();
    const keyOf = (sessionID, id) => `${sessionID}\0${id}`;
    const context = () => ({ runtime, record: recordFor(directory) });
    const emit = (type, properties) => {
      handleEvent({ event: { type, properties } }, context());
    };
    const noteModel = (sessionID, model) => {
      try {
        const found = modelOf2(model);
        if (found === void 0) return;
        if (sessionID !== "") runtime.setModel(sessionID, found.model);
        runtime.startIdentity(found.provider);
      } catch {
      }
    };
    const recordError = (sessionID, callID, tool2, message) => {
      emit("message.part.updated", {
        sessionID,
        part: { type: "tool", tool: tool2, callID, sessionID, state: { status: "error", error: message } }
      });
    };
    const onEvent = (event) => {
      try {
        const type = readString6(event, "type");
        const data = readField7(event, "data");
        const sessionID = readString6(data, "sessionID");
        switch (type) {
          case "session.created": {
            const location = readField7(data, "location");
            const eventLocation = readField7(event, "location");
            const dir = readString6(location, "directory") || readString6(eventLocation, "directory") || directory;
            const version = readField7(data, "version") ?? readField7(app, "version");
            const parentID = readField7(data, "parentID");
            noteSessionDirectory(scope, sessionID, dir);
            if (typeof parentID !== "string" || parentID === "") noteRootSession(scope, sessionID);
            noteModel(sessionID, readField7(data, "model"));
            emit("session.created", {
              sessionID,
              info: { id: sessionID, directory: dir, version, ...typeof parentID === "string" ? { parentID } : {} }
            });
            return;
          }
          case "session.step.started":
            noteModel(sessionID, readField7(data, "model"));
            return;
          case "session.text.ended": {
            const messageID = readString6(data, "assistantMessageID");
            const text = readField7(data, "text");
            const ordinal = readField7(data, "ordinal");
            if (messageID === "" || typeof text !== "string") return;
            emit("message.updated", { sessionID, info: { id: messageID, sessionID, role: "assistant" } });
            emit("message.part.updated", {
              sessionID,
              part: { id: `${messageID}:${typeof ordinal === "number" ? ordinal : 0}`, sessionID, messageID, type: "text", text }
            });
            return;
          }
          case "session.execution.interrupted":
            noteInterrupted(scope, sessionID, nowOf(runtime));
            emit("session.idle", { sessionID });
            return;
          case "session.execution.succeeded":
          case "session.execution.failed":
            emit("session.idle", { sessionID });
            return;
          case "session.deleted":
            emit("session.deleted", { sessionID });
            return;
          case "session.tool.input.started": {
            const id = readString6(data, "id");
            const name = readString6(data, "name");
            if (id !== "" && name !== "") remember(toolNames, keyOf(sessionID, id), name);
            return;
          }
          case "session.tool.failed": {
            const id = readString6(data, "id");
            if (sessionID === "" || id === "") return;
            const name = toolNames.get(keyOf(sessionID, id)) ?? "";
            if (name === V2_CODE_MODE_TOOL) return;
            const error = readField7(data, "error");
            recordError(sessionID, id, v1ToolName(name), readString6(error, "message"));
            return;
          }
          case "mcp.status.changed":
            recordFor(directory).mcpRefreshedAt = void 0;
            return;
          default:
            return;
        }
      } catch {
      }
    };
    const afterHandler = async (event) => {
      try {
        if (!claimHookInput(scope, "tool.execute.after", event)) return;
        const tool2 = readString6(event, "tool");
        const sessionID = readString6(event, "sessionID");
        const id = readString6(event, "id");
        if (tool2 === "" || tool2 === V2_CODE_MODE_TOOL || sessionID === "" || id === "") return;
        const name = v1ToolName(tool2);
        const status = readField7(event, "status");
        let callID = id;
        let compare = true;
        if (!V2_BUILTIN_TOOLS.has(tool2)) {
          const taken = takeCodeModeResult(scope, sessionID, id);
          if (taken !== void 0) {
            callID = taken.callID;
            compare = !taken.concurrent;
          } else {
            const key = keyOf(sessionID, id);
            const seen = afterCounts.get(key) ?? 0;
            remember(afterCounts, key, seen + 1);
            if (seen > 0) {
              callID = `${id}#${seen}`;
              compare = false;
            }
          }
        }
        if (status === "error") {
          runtime.takeDigest(sessionID, callID);
          const error = readField7(readField7(event, "error"), "error");
          recordError(sessionID, callID, name, readString6(error, "reason") || readString6(error, "_tag"));
          return;
        }
        if (!compare) {
          runtime.takeDigest(sessionID, callID);
          recordResult(context(), sessionID, callID, name, false, outputParts(readField7(event, "result")));
          return;
        }
        await toolExecuteAfter(context())(
          { tool: name, sessionID, callID, args: readField7(event, "input") },
          { output: readField7(event, "result") }
        );
      } catch {
      }
    };
    const modelRequest = async (event) => {
      try {
        if (!claimHookInput(scope, "session.model.request", event)) return;
        const kind = readField7(event, "kind");
        if (kind !== void 0 && kind !== "primary") {
          runtime.startIdentity(readString6(readField7(event, "model"), "providerID") || void 0);
          return;
        }
        noteModel(readString6(event, "sessionID"), readField7(event, "model"));
      } catch {
      }
    };
    const tool = ctx.tool;
    if (tool !== void 0 && typeof tool.hook === "function") {
      registrations.track(tool.hook("execute.after", afterHandler));
    }
    const session = ctx.session;
    if (session !== void 0 && typeof session.hook === "function") {
      registrations.track(session.hook("model.request", modelRequest));
    }
    const events = ctx.event;
    if (events !== void 0 && typeof events.subscribe === "function") {
      controller = new AbortController();
      const iterable = events.subscribe({ signal: controller.signal });
      void (async () => {
        try {
          for await (const event of iterable) {
            if (stopped) break;
            if (claimEvent(scope, directory, event)) onEvent(event);
          }
        } catch {
        }
      })().catch(() => void 0);
    }
    return stop;
  } catch {
    stop();
    return void 0;
  }
}

// packages/opencode/src/v2.ts
var SETUP_SENTINEL_KEY = `${SENTINEL_KEY}.v2-setup`;
var SETUP_TOOL_LABEL = "setup";
function v2StatusDetail(capabilities) {
  const gaps = V2_RECORDING_GAPS.length > 0 ? "." + V2_RECORDING_GAPS.join(".") : "";
  return [
    `tools:${capabilities.tools}`,
    `ask:${capabilities.ask}`,
    `mcp:${capabilities.mcp}`,
    `prompt:${capabilities.prompt}`,
    `recording:${capabilities.recording}${gaps}`,
    `identity:${capabilities.identity}`,
    `shell:${capabilities.userShell}`
  ].join("/");
}
var V2_CONTEXT_KEYS = ["tool", "permission", "session", "event"];
function isV2Context(ctx) {
  try {
    if (ctx === null || typeof ctx !== "object") return false;
    return V2_CONTEXT_KEYS.every((key) => key in ctx);
  } catch {
    return false;
  }
}
function readField8(value, key) {
  try {
    if (value === null || typeof value !== "object") return void 0;
    return value[key];
  } catch {
    return void 0;
  }
}
function later2(fn) {
  try {
    const timer = setTimeout(() => {
      try {
        fn();
      } catch {
      }
    }, 0);
    timer.unref?.();
  } catch {
  }
}
function createSetupV2(overrides = {}) {
  const source = overrides ?? {};
  const slotKey = typeof source.sentinelKey === "symbol" ? source.sentinelKey : Symbol.for(SETUP_SENTINEL_KEY);
  const buildToken = typeof source.buildToken === "string" && source.buildToken !== "" ? source.buildToken : BUILD_TOKEN;
  const capabilities = source.capabilities ?? V2_CAPABILITIES;
  let local;
  function freshShared() {
    const { capabilities: _capabilities, sentinelKey: _sentinelKey, ...deps } = source;
    const handle = createRuntime({ ...deps, readAuth: (_dataDir, provider) => v2ProviderIdentity(provider) });
    const directories = /* @__PURE__ */ new Set();
    const shared = {
      handle,
      capabilities,
      directories,
      statusReported: false,
      statusPending: false,
      scope: createV2Scope(directories)
    };
    shared.scope.onActivity = () => reportStatus(shared);
    return shared;
  }
  function claim(shared) {
    try {
      Object.defineProperty(globalThis, slotKey, {
        value: Object.freeze({ module: SETUP_SENTINEL_KEY, build: buildToken, shared }),
        writable: false,
        configurable: false,
        enumerable: false
      });
    } catch {
    }
  }
  function acquire() {
    let foreign;
    let configurable = false;
    try {
      const desc = Object.getOwnPropertyDescriptor(globalThis, slotKey);
      if (desc === void 0) {
        const shared = freshShared();
        claim(shared);
        return { shared };
      }
      configurable = desc.configurable === true;
      if (!("value" in desc)) {
        foreign = "accessor";
      } else {
        const holder = desc.value;
        const own = (key) => {
          const d = holder !== null && typeof holder === "object" ? Object.getOwnPropertyDescriptor(holder, key) : void 0;
          return d !== void 0 && "value" in d ? d.value : void 0;
        };
        const shared = own("shared");
        if (holder === null || typeof holder !== "object" || own("module") !== SETUP_SENTINEL_KEY) {
          foreign = "foreign_value";
        } else if (own("build") !== buildToken) {
          const wellFormed = desc.writable === false && desc.configurable === false && Object.isFrozen(holder);
          if (wellFormed && isBuildToken(own("build"))) {
            if (local === void 0) local = freshShared();
            return { shared: local, otherBuild: true };
          }
          foreign = "other_build";
        } else if (desc.writable !== false || desc.configurable !== false || !Object.isFrozen(holder)) {
          foreign = "forged_holder";
        } else if (shared === void 0 || shared === null || typeof shared !== "object" || !(shared.directories instanceof Set)) {
          foreign = "forged_holder";
        } else {
          return { shared };
        }
      }
    } catch {
      foreign = "unreadable";
    }
    if (local === void 0) local = freshShared();
    if (configurable) claim(local);
    return { shared: local, tampered: foreign };
  }
  function reportStatus(shared) {
    if (shared.statusReported || shared.statusPending) return;
    shared.statusPending = true;
    const runtime = shared.handle.runtime;
    const detail = v2StatusDetail(shared.capabilities);
    later2(() => {
      shared.statusPending = false;
      if (shared.statusReported || runtime.init().signals === void 0) return;
      shared.statusReported = true;
      runtime.reportOnce(SIGNAL_V2_STATUS, SETUP_TOOL_LABEL, detail);
      if (shared.capabilities.tools === "audit") runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, SETUP_TOOL_LABEL, "tools");
    });
  }
  return (ctx) => {
    try {
      if (!isV2Context(ctx)) return Promise.resolve(void 0);
      const { shared, tampered, otherBuild } = acquire();
      const handle = shared.handle;
      const runtime = handle.runtime;
      if (tampered !== void 0) later2(() => runtime.reportOnce(SIGNAL_SENTINEL_TAMPERED, SETUP_TOOL_LABEL, tampered));
      if (otherBuild === true) later2(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, SETUP_TOOL_LABEL, "other_build"));
      const v2 = ctx;
      const rawDirectory = readField8(readField8(v2, "location"), "directory");
      const directory = typeof rawDirectory === "string" ? rawDirectory : "";
      const key = directoryKey(directory) ?? "";
      if (shared.directories.has(key)) {
        later2(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, SETUP_TOOL_LABEL, "second_copy"));
        return Promise.resolve(void 0);
      }
      shared.directories.add(key);
      reportStatus(shared);
      let stopRecording;
      const registrations = createV2Registrations();
      try {
        const client = v2HostClient(v2, directory);
        handle.recordFor(directory, client, []);
        const recordFor = (dir) => handle.recordFor(dir, client);
        const registered = registerV2Enforcement(v2, runtime, recordFor, shared.capabilities, shared.scope, registrations);
        stopRecording = registered ? registerV2Recording(v2, runtime, recordFor, shared.scope, registrations) : void 0;
        if (stopRecording === void 0) {
          later2(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, SETUP_TOOL_LABEL, "registration_fault"));
        }
      } catch {
        later2(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, SETUP_TOOL_LABEL, "registration_fault"));
      }
      let cleaned = false;
      const cleanup = async () => {
        if (cleaned) return;
        cleaned = true;
        try {
          registrations.dispose();
        } catch {
        }
        try {
          stopRecording?.();
          shared.directories.delete(key);
          runtime.instances.release(directory);
          handle.releaseRecord(directory);
        } catch {
        }
      };
      return Promise.resolve(cleanup);
    } catch {
      return Promise.resolve(void 0);
    }
  };
}
var setupV2 = createSetupV2();

// packages/opencode/src/index.ts
var plugin = { id: PLUGIN_ID, server: createServerPlugin(), setup: setupV2 };
var index_default = plugin;
export {
  index_default as default
};
