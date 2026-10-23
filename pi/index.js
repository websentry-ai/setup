/**
 * GENERATED FILE - DO NOT EDIT.
 * Built from unbound-hooks-ts (packages/core + packages/pi) by scripts/build.mjs.
 *
 * Fail-open contract: when the Unbound API cannot be reached, times out, answers non-2xx or
 * returns unparseable JSON, the tool call is ALLOWED. pi treats a thrown handler as a block,
 * so every handler registered here catches everything and returns undefined on failure. The
 * single exception is an org whose last successful response asked for block-on-failure.
 *
 * Headless rule: with no UI available (pi -p / --mode json), a verdict that needs confirmation
 * BLOCKS, because there is no way to ask the user.
 *
 * Tested against pi 0.87.1 on Node >= 22.19.0.
 */

// packages/pi/src/index.ts
import { homedir } from "node:os";

// packages/core/src/accountIdentity.ts
import { execFile as nodeExecFile } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

// packages/core/src/constants.ts
var ENV_API_KEY_PI = "UNBOUND_PI_API_KEY";
var ENV_API_KEY_GENERIC = "UNBOUND_API_KEY";
var ENV_GATEWAY_URL = "UNBOUND_GATEWAY_URL";
var ENV_PI_INSTALL_ROOT = "PI_MANAGED_INSTALL_ROOT";
var DEFAULT_GATEWAY_URL = "https://api.getunbound.ai";
var CONFIG_DIR_NAME = ".unbound";
var CONFIG_FILE_NAME = "config.json";
var CACHE_DIR_NAME = ".unbound";
var CACHE_FILE_NAME = "policy_cache.json";
var PI_AGENT_DIR_SEGMENTS = [".pi", "agent"];
var ENV_PI_AGENT_DIR = "PI_CODING_AGENT_DIR";
var KEY_FINGERPRINT_PREFIX = "sha256:";
var APP_LABEL = "pi";
var HOOK_SOURCE = "pi";
var EVENT_NAME_TOOL_USE = "tool_use";
var EVENT_NAME_SESSION_START = "session_start";
var SESSION_PRESENCE_ROW_ENABLED = false;
var EVENT_NAME_USER_PROMPT = "user_prompt";
var USER_BASH_ID_PREFIX = "ubash_";
var PRETOOL_PATH = "/v1/hooks/pretool";
var ERRORS_PATH = "/v1/hooks/errors";
var TURNLOG_PATH = "/v1/hooks/pi";
var TURNLOG_MODEL = "auto";
var TURNLOG_TOOL_USE_TYPE = "PostToolUse";
var PRETOOL_TIMEOUT_MS = 2e4;
var ERRORS_TIMEOUT_MS = 1e4;
var TURNLOG_TIMEOUT_MS = 1e4;
var CONFIRM_TIMEOUT_MS = 12e4;
var ERROR_REPORT_INTERVAL_MS = 6e4;
var ERROR_CATEGORY_BYPASS = "bypassed_due_to_failure";
var ERROR_CATEGORY_BLOCKED = "blocked_due_to_failure";
var ERROR_CATEGORY_TURNLOG = "turn_log_failed";
var KEY_REJECTION_THRESHOLD = 2;
var BREAKER_FAILURE_THRESHOLD = 3;
var BREAKER_OPEN_MS = 6e4;
var CACHE_TTL_MS = 3e5;
var MAX_REASON_CHARS = 2e3;
var MAX_CACHE_BYTES = 65536;
var MAX_TOOLS_TO_CHECK = 256;
var MAX_TOOL_NAME_CHARS = 64;
var MAX_CONFIG_BYTES = 262144;
var MAX_HASH_BYTES = 4194304;
var MAX_TURN_RESULTS = 500;
var MAX_TOOL_OUTPUT_CHARS = 8192;
var MAX_TURN_OUTPUT_CHARS = 131072;
var OUTPUT_TRUNCATION_MARKER = "\n...unbound: output truncated...\n";
var OUTPUT_REDACTION_MARGIN_CHARS = 4096;
var MAX_TURN_TOOL_CALLS = 500;
var MAX_TOOL_INPUT_BYTES = 16384;
var MAX_COMMAND_CHARS = 8192;
var MAX_PROMPT_CHARS = 8192;
var MAX_ASSISTANT_CHARS = 16384;
var MAX_TOOL_INPUT_VALUE_BYTES = 2048;
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
var DECLINED_REASON = "Declined by user (Unbound policy)";
var CONFIRM_TITLE = "Unbound policy";
var CONFIRM_QUESTION = "Run this command?";
var NO_UI_REASON = "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
var ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable \u2014 please retry";
var NO_KEY_NOTICE = "Unbound: no API key found \u2014 extension inactive";
var BREAKER_OPEN_NOTICE = "Unbound policy engine unreachable \u2014 allowing tool calls for 60 s";
var BREAKER_CLOSED_NOTICE = "Unbound policy engine reachable again \u2014 enforcement resumed";
var KEY_REJECTED_NOTICE = "Unbound: API key rejected \u2014 enforcement inactive";
var KEY_REJECTED_BLOCK_REASON = "Unbound API key rejected \u2014 this organisation enforces fail-closed; contact your admin";
var PI_AUTH_FILE_NAME = "auth.json";
var MAX_AUTH_FILE_BYTES = 65536;
var ANTHROPIC_PROVIDER_ID = "anthropic";
var PI_AUTH_TYPE_OAUTH = "oauth";
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
var MCP_TOOL_APPROVAL_REQUEST_EVENT = "pi-mcp-adapter:tool-approval-request";
var MCP_PROXY_TOOL_NAME = "mcp";
var MCP_NAMESPACE_TOOL_PREFIX = "mcp__";
var MCP_BROKER_ID_PREFIX = "mcpb_";
var MAX_INFLIGHT_MCP_CALLS = 64;
var MAX_MCP_ARGS_BYTES = 524288;
var MAX_PRETOOL_BODY_BYTES = 921600;
var MAX_MCP_SERVER_CONFIG_BYTES = 32768;
var MCP_INFLIGHT_MAX_AGE_MS = 3e5;
var ENV_PI_MCP_CONFIG_MODE = "PI_MCP_CONFIG_MODE";
var MCP_ADAPTER_CONFIG_FILE_NAME = "mcp-adapter.json";
var MCP_CONFIG_FLAG = "--mcp-config";
var MAX_MCP_CONFIG_BYTES = 1048576;

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

// packages/core/src/accountIdentity.ts
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
  return new Promise((resolve) => {
    let timer;
    try {
      timer = setTimeout(() => resolve(fallback), ms);
      timer.unref?.();
    } catch {
      resolve(fallback);
      return;
    }
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
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
function readPiAuth(agentDir) {
  try {
    if (typeof agentDir !== "string" || agentDir === "") return void 0;
    const raw = readSmallRegularFile(join(agentDir, PI_AUTH_FILE_NAME), MAX_AUTH_FILE_BYTES);
    if (raw === void 0) return void 0;
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) return void 0;
    const out = {};
    for (const [provider, value] of Object.entries(parsed)) {
      if (!isRecord(value) || typeof value.type !== "string") continue;
      const entry = { type: value.type };
      if (typeof value.access === "string" && value.access.length > 0) entry.access = value.access;
      if (typeof value.expires === "number" && Number.isFinite(value.expires)) entry.expires = value.expires;
      out[provider] = entry;
    }
    return out;
  } catch {
    return void 0;
  }
}
function chooseProvider(auth, modelProvider) {
  try {
    const fromModel = label(modelProvider);
    if (fromModel !== void 0) return fromModel;
    if (!isRecord(auth)) return void 0;
    const providers = Object.keys(auth);
    return providers.length === 1 ? providers[0] : void 0;
  } catch {
    return void 0;
  }
}
function isAnthropicOAuth(provider, entry) {
  return provider === ANTHROPIC_PROVIDER_ID && entry?.type === PI_AUTH_TYPE_OAUTH;
}
async function fetchAnthropicProfile(token, opts = {}) {
  try {
    if (typeof token !== "string" || token.length === 0) return void 0;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const fetchImpl = opts.fetch ?? globalThis.fetch;
    const request = attempt(async () => {
      const res = await fetchImpl(opts.url ?? ANTHROPIC_PROFILE_URL, {
        method: "GET",
        headers: {
          authorization: `Bearer ${token}`,
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
    const provider = input.provider;
    const entry = provider === void 0 ? void 0 : input.auth[provider];
    if (entry !== void 0) {
      if (isAnthropicOAuth(provider, entry)) {
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
var defaultExecFile = (file, args, opts) => new Promise((resolve) => {
  try {
    nodeExecFile(
      file,
      [...args],
      { timeout: opts.timeoutMs, maxBuffer: opts.maxBytes, windowsHide: true, encoding: "utf8", cwd: tmpdir() },
      (error, stdout) => resolve(error === null && typeof stdout === "string" ? stdout : void 0)
    );
  } catch {
    resolve(void 0);
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
    const auth = readPiAuth(opts.agentDir);
    if (auth === void 0) return void 0;
    const provider = chooseProvider(auth, modelProvider);
    const entry = provider === void 0 ? void 0 : auth[provider];
    const now = (opts.now ?? Date.now)();
    const live = isAnthropicOAuth(provider, entry) && entry?.access !== void 0 && entry.expires !== void 0 && entry.expires > now;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const [profile, deviceSerial] = await Promise.all([
      live && entry?.access !== void 0 ? fetchAnthropicProfile(entry.access, {
        timeoutMs,
        ...opts.fetch === void 0 ? {} : { fetch: opts.fetch },
        ...opts.profileUrl === void 0 ? {} : { url: opts.profileUrl }
      }) : Promise.resolve(void 0),
      readDeviceSerial({ ...opts, timeoutMs })
    ]);
    return buildAccountIdentity({
      auth,
      provider,
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

// packages/core/src/cache.ts
import { chmodSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute, join as join2 } from "node:path";

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
    hydrate(snapshot2) {
      if (snapshot2 === null || typeof snapshot2 !== "object" || Array.isArray(snapshot2)) return;
      if (toolsSyncedAt === void 0) {
        const tools = parseToolsToCheck(snapshot2.tools_to_check);
        const syncedAt = parseTimestamp(snapshot2.tools_synced_at);
        if (tools !== void 0 && syncedAt !== void 0) {
          toolsToCheck = tools;
          toolsSyncedAt = syncedAt;
        }
      }
      if (fetchedAt === void 0) {
        const action = parseFailureAction(snapshot2.policy_check_failure_action);
        if (action !== void 0) failureAction = action;
        const fetched = parseTimestamp(snapshot2.fetched_at);
        if (fetched !== void 0) fetchedAt = fetched;
      }
    }
  };
}
var policyState = createPolicyState();

// packages/core/src/payload.ts
var PATH_DEFAULTING_TOOLS = ["grep", "find", "ls"];
var PATH_REQUIRED_TOOLS = ["read", "write", "edit"];
var PATH_DEFAULTING = new Set(PATH_DEFAULTING_TOOLS);
var PATH_REQUIRED = new Set(PATH_REQUIRED_TOOLS);
var NATIVE_FILE_TOOLS = /* @__PURE__ */ new Set([
  ...PATH_DEFAULTING_TOOLS,
  ...PATH_REQUIRED_TOOLS
]);
function resolveFilePath(toolName, toolInput, cwd) {
  const isDefaulting = PATH_DEFAULTING.has(toolName);
  if (!isDefaulting && !PATH_REQUIRED.has(toolName)) return void 0;
  const path = toolInput.path;
  if (typeof path === "string" && path.length > 0) return path;
  return isDefaulting ? cwd : void 0;
}
var ALLOWED_TOOL_INPUT_KEYS = new Set(TOOL_INPUT_ALLOWLIST);
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
function sanitizeToolInput(toolInput) {
  const out = {};
  if (toolInput === null || typeof toolInput !== "object" || Array.isArray(toolInput)) return out;
  let dropped = false;
  let truncated = false;
  for (const [key, value] of Object.entries(toolInput)) {
    if (!ALLOWED_TOOL_INPUT_KEYS.has(key)) {
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
function auditToolInput(toolInput, command) {
  const isObject = toolInput !== null && typeof toolInput === "object" && !Array.isArray(toolInput);
  const source = isObject ? { ...toolInput } : {};
  delete source.command;
  const out = sanitizeToolInput(source);
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
function auditMcpArgs(args, maxBytes = MAX_TOOL_INPUT_BYTES) {
  try {
    if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
    const serialised = JSON.stringify(args);
    if (typeof serialised !== "string") return { _truncated: true };
    const originalBytes = Buffer.byteLength(serialised);
    if (originalBytes <= maxBytes) {
      const cloned = JSON.parse(serialised);
      return cloned !== null && typeof cloned === "object" && !Array.isArray(cloned) ? cloned : {};
    }
    const capped = { _truncated: true, _original_bytes: originalBytes };
    let usedBytes = Buffer.byteLength(JSON.stringify(capped));
    for (const key of Object.keys(args)) {
      const raw = args[key];
      if (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "boolean") continue;
      const value = typeof raw === "string" ? sliceToBytes(raw, MAX_TOOL_INPUT_VALUE_BYTES) : raw;
      const entryBytes = Buffer.byteLength(JSON.stringify(key)) + Buffer.byteLength(JSON.stringify(value)) + 2;
      if (usedBytes + entryBytes > maxBytes) continue;
      defineData(capped, key, value);
      usedBytes += entryBytes;
    }
    return capped;
  } catch {
    return { _truncated: true };
  }
}
function buildPretoolPayload(input) {
  const mcp = input.mcp;
  const metadata = { cwd: input.cwd };
  if (mcp !== void 0) {
    metadata.mcp_server = mcp.server;
    metadata.mcp_tool = mcp.tool;
    applyWireArgs(metadata, mcpArgsForWire(mcp.args));
    if (mcp.serverConfig !== void 0 && serialisedBytes(mcp.serverConfig) <= MAX_MCP_SERVER_CONFIG_BYTES) {
      metadata.mcp_server_config = mcp.serverConfig;
    }
    if (typeof mcp.origin === "string" && mcp.origin !== "") metadata.mcp_origin = mcp.origin;
  } else {
    metadata.tool_input = capToolInput(sanitizeToolInput(input.toolInput));
    const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd);
    if (filePath !== void 0) metadata.file_path = filePath;
  }
  const capped = capCommand(mcp === void 0 ? input.command : "");
  if (capped.truncated) {
    metadata.command_truncated = true;
    metadata.command_original_chars = input.command.length;
  }
  const preToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears. A resolved MCP call is
    // named the way the gateway and the backend parse MCP names, `mcp__<server>__<tool>`.
    tool_name: mcp === void 0 ? input.toolName : `mcp__${mcp.server}__${mcp.tool}`,
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
    unbound_app_label: APP_LABEL,
    client_entrypoint: input.clientEntrypoint
  };
  if (input.pullPolicies === true) body.pull_policies = true;
  const finished = withAccountIdentity(body, input.accountIdentity);
  if (mcp !== void 0) fitMcpBody(finished, mcp.args);
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
function buildPromptPayload(input) {
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
    unbound_app_label: APP_LABEL,
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
function resolveCachePath(env, homeDir) {
  const base = resolvePiAgentDir(env, homeDir);
  if (base === void 0) return void 0;
  return join2(base, CACHE_DIR_NAME, CACHE_FILE_NAME);
}
function resolvePiAgentDir(env, homeDir) {
  try {
    let base = expandTilde(env?.[ENV_PI_AGENT_DIR], typeof homeDir === "string" ? homeDir : "");
    if (base === void 0 || !isAbsolute(base)) {
      if (typeof homeDir !== "string" || homeDir.length === 0 || !isAbsolute(homeDir)) return void 0;
      base = join2(homeDir, ...PI_AGENT_DIR_SEGMENTS);
    }
    return isAbsolute(base) ? base : void 0;
  } catch {
    return void 0;
  }
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
function shouldSkipFileTool(toolName, cache, now) {
  if (typeof toolName !== "string" || !NATIVE_FILE_TOOLS.has(toolName)) return false;
  if (!isToolsFresh(cache, now)) return false;
  const tools = cache?.tools_to_check;
  if (!Array.isArray(tools)) return false;
  return !tools.includes(toolName);
}
function shouldSkipFileToolFromState(toolName, state, now) {
  return shouldSkipFileTool(
    toolName,
    { tools_synced_at: state.getToolsSyncedAt(), tools_to_check: state.getToolsToCheck() },
    now
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
  const token = candidate.replace(/[^A-Za-z0-9_]/g, "");
  return token.length > 0 ? token.slice(0, MAX_ERROR_CLASS_CHARS) : "Error";
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
      const res = await resolveFetch()(`${opts.baseUrl}${TURNLOG_PATH}`, {
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

// packages/core/src/heartbeat.ts
function buildHeartbeatPayload(input) {
  const body = {
    conversation_id: input.sessionId,
    model: input.model !== void 0 && input.model.length > 0 ? input.model : TURNLOG_MODEL,
    event_name: EVENT_NAME_SESSION_START,
    // Blank tool name, blank command, no `file_path`. See the header: this is what keeps the request
    // out of the command-policy evaluator.
    pre_tool_use_data: {
      tool_name: "",
      command: "",
      metadata: { cwd: input.cwd, has_ui: input.hasUI, pi_version: input.piVersion }
    },
    // Empty rather than absent: the field is required by the server type, and a heartbeat has no
    // prompt to report. Sending a blank prompt through the guardrail path is exactly what §C2 warns
    // against, which is why `event_name` above is not `user_prompt`.
    messages: [],
    unbound_app_label: APP_LABEL,
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

// packages/core/src/config.ts
import { isAbsolute as isAbsolute2, join as join3 } from "node:path";
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function readUnboundConfig(homeDir) {
  if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute2(homeDir)) return {};
  const raw = readSmallRegularFile(join3(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), MAX_CONFIG_BYTES);
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
function resolveApiKey(env, homeDir) {
  const fromEnv = usableString(env[ENV_API_KEY_PI]) ?? usableString(env[ENV_API_KEY_GENERIC]);
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

// packages/core/src/piVersion.ts
import { readFileSync as readFileSync2 } from "node:fs";
import { dirname as dirname2, join as join4 } from "node:path";
var PI_PACKAGE_NAME = "@earendil-works/pi-coding-agent";
var MAX_WALK_UP_LEVELS = 8;
var MAX_VERSION_CHARS = 32;
function readManagedInstallVersion(env) {
  const root = env[ENV_PI_INSTALL_ROOT];
  if (typeof root !== "string" || root.length === 0) return void 0;
  try {
    const version = readFileSync2(join4(root, "current-version"), "utf8").trim();
    return version.length > 0 ? version : void 0;
  } catch {
    return void 0;
  }
}
function readVersionFromArgv(argv1) {
  if (typeof argv1 !== "string" || argv1.length === 0) return void 0;
  let dir = dirname2(argv1);
  for (let level = 0; level < MAX_WALK_UP_LEVELS; level += 1) {
    try {
      const parsed = JSON.parse(readFileSync2(join4(dir, "package.json"), "utf8"));
      if (parsed !== null && typeof parsed === "object") {
        const pkg = parsed;
        if (pkg.name === PI_PACKAGE_NAME && typeof pkg.version === "string" && pkg.version.length > 0) {
          return pkg.version;
        }
      }
    } catch {
    }
    const parent = dirname2(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return void 0;
}
function sanitizeVersion(version) {
  const cleaned = version.replace(/[^A-Za-z0-9._+-]/g, "").slice(0, MAX_VERSION_CHARS);
  return cleaned.length > 0 ? cleaned : "unknown";
}
function resolveClientEntrypoint(env, argv1) {
  let version = "unknown";
  try {
    const found = readManagedInstallVersion(env) ?? readVersionFromArgv(argv1);
    if (found !== void 0) version = sanitizeVersion(found);
  } catch {
    version = "unknown";
  }
  return `pi/${version}`;
}

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
function bodyBytes(payload) {
  try {
    const text = JSON.stringify(payload);
    return typeof text === "string" ? Buffer.byteLength(text) : Number.POSITIVE_INFINITY;
  } catch {
    return Number.POSITIVE_INFINITY;
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
      if (bodyBytes(payload) >= MAX_PRETOOL_BODY_BYTES) {
        const blocked2 = opts.state.getFailureAction() === "block";
        opts.telemetry.reportBypass({ errorClass: "PayloadTooLarge", toolName, elapsedMs: 0, blocked: blocked2 });
        return blocked2 ? { kind: "unavailable" } : { kind: "allow" };
      }
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
        `pi hook ${category}: ${ctx.errorClass} for tool=${ctx.toolName} after ${ctx.elapsedMs}ms`,
        apiKey
      );
      const body = {
        errors: [{ message, timestamp: new Date(at).toISOString(), category }],
        hook_source: HOOK_SOURCE
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
function textOf(part) {
  if (part === null || typeof part !== "object") return void 0;
  const record = part;
  return record.type === "text" && typeof record.text === "string" ? record.text : void 0;
}
function flatten(value) {
  return Buffer.from(value, "utf8").toString("utf8");
}
function headOf(segments, n) {
  let out = "";
  for (const segment of segments) {
    const room = n - out.length;
    if (room <= 0) break;
    out += segment.length <= room ? segment : segment.slice(0, room);
  }
  return out;
}
function tailOf(segments, n) {
  let out = "";
  for (let i = segments.length - 1; i >= 0; i -= 1) {
    const room = n - out.length;
    if (room <= 0) break;
    const segment = segments[i];
    out = (segment.length <= room ? segment : segment.slice(segment.length - room)) + out;
  }
  return out;
}
function captureText(parts, maxChars, redact, margin = OUTPUT_REDACTION_MARGIN_CHARS) {
  try {
    if (!Array.isArray(parts)) return void 0;
    const texts = [];
    for (const part of parts) {
      const text = textOf(part);
      if (text !== void 0) texts.push(text);
    }
    if (texts.length === 0) return void 0;
    const clean = (text) => redact === void 0 ? text : redact(text);
    let total = 0;
    for (let i = 0; i < texts.length; i += 1) total += (i > 0 ? 1 : 0) + texts[i].length;
    const cap = Number.isFinite(maxChars) && maxChars > 0 ? Math.floor(maxChars) : 0;
    if (total <= cap) return { text: flatten(clean(texts.join("\n"))) };
    const headBudget = Math.ceil(cap / 2);
    const tailBudget = cap - headBudget;
    const extra = Number.isFinite(margin) && margin > 0 ? Math.floor(margin) : 0;
    const segments = [];
    for (let i = 0; i < texts.length; i += 1) {
      if (i > 0) segments.push("\n");
      segments.push(texts[i]);
    }
    const head = clean(headOf(segments, headBudget + extra)).slice(0, headBudget);
    const redactedTail = clean(tailOf(segments, tailBudget + extra));
    const tail = redactedTail.slice(Math.max(0, redactedTail.length - tailBudget));
    return {
      text: flatten(head) + OUTPUT_TRUNCATION_MARKER + flatten(tail),
      truncated: true,
      original_chars: total
    };
  } catch {
    return void 0;
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

// packages/pi/src/agentEnd.ts
function assistantTextFrom(messages) {
  try {
    const list = Array.isArray(messages) ? messages : [];
    const chunks = [];
    for (const message of list) {
      if (message === null || typeof message !== "object") continue;
      const { role, content } = message;
      if (role !== "assistant") continue;
      if (!Array.isArray(content)) continue;
      const parts = [];
      for (const part of content) {
        if (part === null || typeof part !== "object") continue;
        const { type, text } = part;
        if (type !== "text") continue;
        if (typeof text !== "string" || text === "") continue;
        parts.push(text);
      }
      if (parts.length > 0) chunks.push(parts.join("\n"));
    }
    return chunks.join("\n");
  } catch {
    return "";
  }
}
var TURNLOG_LABEL = "agent_end";
var USER_BASH_LABEL = "user_bash";
function cwdOf(ctx) {
  try {
    return typeof ctx?.cwd === "string" ? ctx.cwd : "";
  } catch {
    return "";
  }
}
function dispatchTurnLog(record, cwd, assistantText, label2, deps) {
  try {
    const completedAtMs = (deps.now ?? Date.now)();
    const body = buildTurnLogBody(record, {
      cwd,
      completedAtMs,
      assistantText,
      ...deps.apiKey === void 0 ? {} : { apiKey: deps.apiKey },
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    });
    const dispatchedAtMs = completedAtMs;
    void deps.client.postTurnLog(body).then((ok) => {
      if (ok) return;
      deps.telemetry?.reportTurnLogFailure({
        errorClass: "TurnLogFailed",
        toolName: label2,
        elapsedMs: (deps.now ?? Date.now)() - dispatchedAtMs
      });
    }).catch(() => {
    });
  } catch {
  }
}
function handleAgentEnd(event, ctx, deps) {
  try {
    const record = deps.store.take();
    if (!shouldPostTurn(record)) return void 0;
    let assistantText = "";
    try {
      assistantText = assistantTextFrom(event?.messages);
    } catch {
    }
    dispatchTurnLog(record, cwdOf(ctx), assistantText, TURNLOG_LABEL, deps);
  } catch {
  }
  return void 0;
}
function postStandaloneTurn(entry, ctx, sessionId, deps) {
  try {
    if (entry === null || typeof entry !== "object") return void 0;
    const now = (deps.now ?? Date.now)();
    const call = {
      tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
      tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
      decision: typeof entry.decision === "string" ? entry.decision : "",
      ts: now
    };
    const input = entry.tool_input;
    if (input !== null && typeof input === "object" && !Array.isArray(input)) {
      call.tool_input = { ...input };
    }
    const record = { tool_calls: [call], results: [], started_at: now };
    if (typeof sessionId === "string" && sessionId !== "") {
      record.session_id = sessionId;
      call.session_id = sessionId;
    }
    if (!shouldPostTurn(record)) return void 0;
    dispatchTurnLog(record, cwdOf(ctx), "", USER_BASH_LABEL, deps);
  } catch {
  }
  return void 0;
}

// packages/pi/src/narrow.ts
var SHELL_TOOLS = /* @__PURE__ */ new Set(["bash", "powershell"]);
function isShellCall(e) {
  if (!SHELL_TOOLS.has(e.toolName)) return false;
  const input = e.input;
  return typeof input === "object" && input !== null && typeof input.command === "string";
}

// packages/pi/src/ui.ts
function notifySafe(ctx, message, level) {
  try {
    const safe = redactSecrets(message);
    if (ctx.hasUI) {
      ctx.ui.notify(safe, level);
      return;
    }
    process.stderr.write(`${safe}
`);
  } catch {
  }
}
async function confirmWithTimeout(ctx, title, message, timeoutMs = CONFIRM_TIMEOUT_MS) {
  try {
    return await ctx.ui.confirm(title, message, { timeout: timeoutMs, signal: ctx.signal });
  } catch {
    return false;
  }
}

// packages/pi/src/decide.ts
function promptOf(deps) {
  try {
    const prompt = deps.currentPrompt?.();
    if (typeof prompt !== "string" || prompt === "") return "";
    return capCommand(prompt, MAX_PROMPT_CHARS).command;
  } catch {
    return "";
  }
}
function noteDecision(deps, entry) {
  noteSafe(() => deps.onDecision?.(entry));
}
function noteSafe(fn) {
  try {
    fn?.();
  } catch {
  }
}
async function decideToolCall(event, ctx, deps) {
  try {
    const shell = isShellCall(event);
    const command = shell ? event.input.command : "";
    const toolInput = event.input ?? {};
    const filePath = resolveFilePath(event.toolName, toolInput, ctx.cwd);
    if (command.trim() === "" && filePath === void 0) return void 0;
    const auditInput = auditToolInput(toolInput, command);
    const now = (deps.now ?? Date.now)();
    const state = deps.state ?? policyState;
    const toolsConfirmed = state.getToolsConfirmed();
    if (toolsConfirmed && NATIVE_FILE_TOOLS.has(event.toolName) && shouldSkipFileToolFromState(event.toolName, state, now)) {
      noteDecision(deps, {
        tool_name: event.toolName,
        tool_use_id: event.toolCallId,
        decision: "skipped",
        // Recorded on this path too: a skip is still a call the developer made, and the path it was
        // made against is what makes the row readable.
        tool_input: auditInput
      });
      return void 0;
    }
    const pullPolicies = !toolsConfirmed || !areToolsFresh(state.getToolsSyncedAt(), now);
    const payload = buildPretoolPayload({
      toolName: event.toolName,
      command,
      toolUseId: event.toolCallId,
      toolInput,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      pullPolicies,
      // Read here, after both early returns: a skipped call never pays for it.
      lastUserPrompt: promptOf(deps),
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    });
    const hooks = deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, event.toolName, hooks);
    noteDecision(deps, {
      tool_name: event.toolName,
      tool_use_id: event.toolCallId,
      decision: outcome.kind,
      tool_input: auditInput
    });
    return await applyOutcome(outcome, ctx);
  } catch {
    return void 0;
  }
}
async function confirmBrokered(ui, reason, signal) {
  try {
    if (ui.hasUI !== true) {
      notifySafe(ui, NO_UI_REASON, "warning");
      return "deny";
    }
    notifySafe(ui, reason, "warning");
    const dialogCtx = { hasUI: true, ui: ui.ui, signal: signal instanceof AbortSignal ? signal : void 0 };
    const accepted = await confirmWithTimeout(dialogCtx, CONFIRM_TITLE, CONFIRM_QUESTION);
    return accepted ? "allow_once" : "deny";
  } catch {
    return "deny";
  }
}
async function decideMcpApproval(input, deps) {
  try {
    const { call } = input;
    const toolName = `mcp__${call.server}__${call.tool}`;
    const now = (deps.now ?? Date.now)();
    const state = deps.state ?? policyState;
    const pullPolicies = !state.getToolsConfirmed() || !areToolsFresh(state.getToolsSyncedAt(), now);
    const payload = buildPretoolPayload({
      toolName,
      command: "",
      toolUseId: input.toolUseId,
      toolInput: {},
      cwd: input.cwd,
      sessionId: input.sessionId,
      model: input.model,
      clientEntrypoint: deps.entrypoint,
      pullPolicies,
      lastUserPrompt: promptOf(deps),
      mcp: call,
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    });
    const ui = input.ui;
    const hooks = deps.hooks ?? { notify: (message, level) => ui === void 0 ? void 0 : notifySafe(ui, message, level) };
    const outcome = await deps.checker.checkTool(payload, toolName, hooks);
    noteDecision(deps, {
      tool_name: toolName,
      tool_use_id: input.toolUseId,
      decision: outcome.kind,
      tool_input: auditMcpArgs(call.args)
    });
    if (input.signal?.aborted === true) return "abstain";
    switch (outcome.kind) {
      case "allow":
        return "abstain";
      case "deny":
        if (ui !== void 0) notifySafe(ui, outcome.reason ?? GENERIC_DENY_REASON, "error");
        return "deny";
      case "confirm":
        if (ui === void 0) return "deny";
        return await confirmBrokered(ui, outcome.reason ?? GENERIC_DENY_REASON, input.signal);
      case "unavailable":
        if (ui !== void 0) notifySafe(ui, outcome.reason ?? ENGINE_UNAVAILABLE_REASON, "error");
        return "deny";
    }
    return "abstain";
  } catch {
    return "abstain";
  }
}
async function applyOutcome(outcome, ctx) {
  switch (outcome.kind) {
    case "allow":
      return void 0;
    case "deny": {
      const reason = outcome.reason;
      notifySafe(ctx, reason ?? GENERIC_DENY_REASON, "error");
      return {
        block: true,
        reason: reason === void 0 ? GENERIC_DENY_REASON : DENY_PREFIX + reason
      };
    }
    case "confirm": {
      if (!ctx.hasUI) return { block: true, reason: NO_UI_REASON };
      const reason = outcome.reason ?? GENERIC_DENY_REASON;
      notifySafe(ctx, reason, "warning");
      const accepted = await confirmWithTimeout(ctx, CONFIRM_TITLE, CONFIRM_QUESTION);
      return accepted ? void 0 : { block: true, reason: DECLINED_REASON };
    }
    case "unavailable":
      return { block: true, reason: outcome.reason ?? ENGINE_UNAVAILABLE_REASON };
  }
  return void 0;
}

// packages/pi/src/mcpBroker.ts
import { createHash as createHash3, randomBytes as randomBytes2 } from "node:crypto";
var ANSWERS = /* @__PURE__ */ new Set(["allow_once", "deny", "abstain"]);
function isRecord2(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function snapshot(data) {
  if (!isRecord2(data)) return void 0;
  const claim = data.claim;
  if (typeof claim !== "function") return void 0;
  const serverName = data.serverName;
  const originalToolName = data.originalToolName;
  if (typeof serverName !== "string" || serverName === "") return void 0;
  if (typeof originalToolName !== "string" || originalToolName === "") return void 0;
  const prefixedToolName = typeof data.prefixedToolName === "string" ? data.prefixedToolName : "";
  const args = isRecord2(data.args) ? data.args : {};
  const origin = typeof data.origin === "string" ? data.origin : "";
  const signal = data.signal;
  return {
    serverName,
    originalToolName,
    prefixedToolName,
    args,
    origin,
    signal: signal instanceof AbortSignal ? signal : void 0,
    claim: (handler) => claim.call(data, handler)
  };
}
function createMcpApprovalListener(deps) {
  let reportedPreemption = false;
  return (data) => {
    try {
      const request = snapshot(data);
      if (request === void 0) return;
      if (!deps.active()) return;
      const { claim, ...call } = request;
      const claimed = claim(async () => {
        try {
          if (call.signal?.aborted === true) return "abstain";
          const answer = await deps.decide(call);
          return typeof answer === "string" && ANSWERS.has(answer) ? answer : "abstain";
        } catch {
          return "abstain";
        }
      });
      if (claimed === false && !reportedPreemption) {
        reportedPreemption = true;
        try {
          deps.preempted?.(call);
        } catch {
        }
      }
    } catch {
    }
  };
}
function stableKey(value) {
  try {
    const seen = /* @__PURE__ */ new Set();
    const walk = (v, depth) => {
      if (depth > 64) throw new Error("too deep");
      if (v === null || typeof v !== "object") return v;
      if (seen.has(v)) throw new Error("cycle");
      seen.add(v);
      let out;
      if (Array.isArray(v)) out = v.map((item) => walk(item, depth + 1));
      else {
        const sorted = {};
        for (const key of Object.keys(v).sort()) {
          Object.defineProperty(sorted, key, {
            value: walk(v[key], depth + 1),
            enumerable: true,
            writable: true,
            configurable: true
          });
        }
        out = sorted;
      }
      seen.delete(v);
      return out;
    };
    const text = JSON.stringify(walk(value, 0));
    return typeof text === "string" ? text : void 0;
  } catch {
    return void 0;
  }
}
function mayBeWrapper(toolName) {
  return toolName === MCP_PROXY_TOOL_NAME || toolName.startsWith(MCP_NAMESPACE_TOOL_PREFIX);
}
function wrapperArgsKey(input) {
  try {
    const raw = isRecord2(input) ? input.args : void 0;
    if (raw === void 0 || raw === "") return stableKey({});
    if (typeof raw === "string") return stableKey(JSON.parse(raw));
    return stableKey(raw);
  } catch {
    return void 0;
  }
}
function directArgsKey(input) {
  return stableKey(isRecord2(input) ? input : {});
}
var ENCODED_SERVER_NAMESPACE_MARKER = "_mcpns_";
var MAX_SERVER_NAMESPACE_LENGTH = 59;
function encodeServerNamespace(name) {
  return Array.from(name, (character) => {
    if (character === "_") return "__";
    return /^[A-Za-z0-9]$/.test(character) ? character : `_${character.codePointAt(0).toString(16)}_`;
  }).join("");
}
function formatServerNamespace(serverName) {
  const normalized = serverName.replace(/-/g, "_");
  const safe = /^[A-Za-z0-9_]*$/.test(normalized) && !normalized.startsWith(ENCODED_SERVER_NAMESPACE_MARKER);
  const body = safe ? normalized : encodeServerNamespace(normalized);
  const namespace = safe ? body : `${ENCODED_SERVER_NAMESPACE_MARKER}${body}`;
  if (namespace.length <= MAX_SERVER_NAMESPACE_LENGTH) return namespace;
  const digest = createHash3("sha256").update(namespace, "utf8").digest("hex").slice(0, 16);
  const hashPrefix = `${ENCODED_SERVER_NAMESPACE_MARKER}_h_`;
  const head = body.slice(0, MAX_SERVER_NAMESPACE_LENGTH - hashPrefix.length - digest.length - 1);
  return `${hashPrefix}${head}_${digest}`;
}
function wrapperServerMatches(entry, serverName) {
  if (entry.toolName === MCP_PROXY_TOOL_NAME) return entry.server === void 0 || entry.server === serverName;
  const ns = entry.toolName.slice(MCP_NAMESPACE_TOOL_PREFIX.length);
  return ns !== "" && ns === formatServerNamespace(serverName);
}
function createInflightCalls(max, maxAgeMs, now = Date.now) {
  let entries = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : 1;
  const expire = () => {
    const cutoff = now() - maxAgeMs;
    entries = entries.filter((entry) => entry.at >= cutoff);
  };
  return {
    remember(entry, sessionId) {
      try {
        if (typeof entry.toolCallId !== "string" || entry.toolCallId === "") return;
        if (typeof entry.toolName !== "string" || entry.toolName === "") return;
        let tool;
        if (isRecord2(entry.input) && typeof entry.input.tool === "string") tool = entry.input.tool;
        let server;
        if (isRecord2(entry.input) && typeof entry.input.server === "string" && entry.input.server !== "") {
          server = entry.input.server;
        }
        expire();
        entries.push({
          toolCallId: entry.toolCallId,
          toolName: entry.toolName,
          tool,
          server,
          directKey: directArgsKey(entry.input),
          wrapperKey: mayBeWrapper(entry.toolName) ? wrapperArgsKey(entry.input) : void 0,
          sessionId: typeof sessionId === "string" ? sessionId : "",
          at: now()
        });
        while (entries.length > cap) entries.shift();
      } catch {
      }
    },
    forget(toolCallId) {
      try {
        if (typeof toolCallId !== "string") return;
        entries = entries.filter((entry) => entry.toolCallId !== toolCallId);
      } catch {
      }
    },
    keepSession(sessionId) {
      try {
        if (typeof sessionId !== "string" || sessionId === "") return;
        entries = entries.filter((entry) => entry.sessionId === "" || entry.sessionId === sessionId);
      } catch {
      }
    },
    claim(serverName, prefixedToolName, originalToolName, args) {
      try {
        expire();
        const argsKey = stableKey(isRecord2(args) ? args : {});
        if (argsKey === void 0) return void 0;
        const index = entries.findIndex((entry) => {
          if (prefixedToolName !== "" && entry.toolName === prefixedToolName && entry.directKey === argsKey) {
            return true;
          }
          return mayBeWrapper(entry.toolName) && entry.wrapperKey === argsKey && wrapperServerMatches(entry, serverName) && entry.tool !== void 0 && (entry.tool === originalToolName || prefixedToolName !== "" && entry.tool === prefixedToolName);
        });
        if (index === -1) return void 0;
        const [found] = entries.splice(index, 1);
        return found?.toolCallId;
      } catch {
        return void 0;
      }
    },
    size() {
      return entries.length;
    }
  };
}
function mintBrokerId() {
  return MCP_BROKER_ID_PREFIX + randomBytes2(10).toString("hex");
}

// packages/pi/src/mcpConfig.ts
import { closeSync, constants as fsConstants, fstatSync, lstatSync as lstatSync2, openSync, readSync, statSync } from "node:fs";
import { isAbsolute as isAbsolute3, join as join5 } from "node:path";
var KNOWN_SERVER_KEYS = /* @__PURE__ */ new Set([
  "command",
  "args",
  "socket",
  "env",
  "inheritEnv",
  "cwd",
  "url",
  "caFile",
  "headers",
  "requestHeadersCommand",
  "auth",
  "bearerToken",
  "bearerTokenEnv",
  "bearerTokenStore",
  "oauth",
  "lifecycle",
  "idleTimeout",
  "requestTimeoutMs",
  "exposeResources",
  "directTools",
  "toolPrefix",
  "includeTools",
  "excludeTools",
  "searchKeywords",
  "approveTools",
  "debug",
  "trace",
  "httpTransport",
  "pluginDataDir",
  "literalEnv",
  "protocolVersion",
  "tasks",
  "disabled",
  // Not read by the adapter at all (no transport selection reads it); common in `.mcp.json` files.
  "type"
]);
var KNOWN_TOP_LEVEL_KEYS = /* @__PURE__ */ new Set(["mcpServers", "settings", "$schema"]);
var UNMODELLED_SETTINGS_KEYS = [
  "ancestorConfigRoots",
  "agentPluginPaths",
  "hostConfigDiscovery",
  "jev"
];
var ENV_PI_PACKAGE_DIR = "PI_PACKAGE_DIR";
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
function hasMcpConfigFlag(argv) {
  try {
    if (!Array.isArray(argv)) return false;
    return argv.some((arg) => arg === MCP_CONFIG_FLAG || typeof arg === "string" && arg.startsWith(`${MCP_CONFIG_FLAG}=`));
  } catch {
    return true;
  }
}
function mcpConfigSources(options, cwd) {
  try {
    const env = options.env ?? {};
    const homeDir = options.homeDir;
    if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute3(homeDir)) return void 0;
    if (typeof cwd !== "string" || cwd === "" || !isAbsolute3(cwd)) return void 0;
    if (hasMcpConfigFlag(options.argv)) return void 0;
    const packageDir = env[ENV_PI_PACKAGE_DIR];
    if (typeof packageDir === "string" && packageDir !== "") return void 0;
    const agentEnv = env[ENV_PI_AGENT_DIR];
    let agentDir;
    if (typeof agentEnv === "string" && agentEnv !== "") {
      if (!isAbsolute3(agentEnv)) return void 0;
      agentDir = agentEnv;
    } else {
      agentDir = join5(homeDir, ".pi", "agent");
    }
    const adapterFile = join5(agentDir, MCP_ADAPTER_CONFIG_FILE_NAME);
    const mode = env[ENV_PI_MCP_CONFIG_MODE];
    if (typeof mode === "string" && mode.trim().toLowerCase() === "exclusive") return [adapterFile];
    const sources = [];
    for (const path of [
      join5(homeDir, ".config", "mcp", "mcp.json"),
      join5(homeDir, ".agents", "mcp.json"),
      join5(homeDir, ".agents", "mcp", "mcp.json")
    ]) {
      if (path !== adapterFile) sources.push(path);
    }
    sources.push(adapterFile);
    const project = join5(cwd, ".mcp.json");
    if (project !== adapterFile) sources.push(project);
    sources.push(join5(cwd, ".pi", MCP_ADAPTER_CONFIG_FILE_NAME));
    return [...new Set(sources)];
  } catch {
    return void 0;
  }
}
function isMissing(error) {
  const code = error?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}
function readSource(path) {
  let fd;
  try {
    try {
      fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    } catch (error) {
      return isMissing(error) ? { kind: "absent" } : { kind: "failed" };
    }
    const stats = fstatSync(fd);
    if (!stats.isFile()) return { kind: "failed" };
    if (!Number.isFinite(stats.size) || stats.size > MAX_MCP_CONFIG_BYTES) return { kind: "failed" };
    const buffer = Buffer.alloc(MAX_MCP_CONFIG_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read <= 0) break;
      total += read;
    }
    if (total > MAX_MCP_CONFIG_BYTES) return { kind: "failed" };
    return { kind: "text", text: buffer.subarray(0, total).toString("utf8") };
  } catch {
    return { kind: "failed" };
  } finally {
    if (fd !== void 0) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}
function modelledServers(text) {
  const raw = text.charCodeAt(0) === 65279 ? text.slice(1) : text;
  if (raw.trim() === "") return "empty";
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;
  for (const key of Object.keys(parsed)) if (!KNOWN_TOP_LEVEL_KEYS.has(key)) return null;
  if (Object.hasOwn(parsed, "settings")) {
    const settings = parsed.settings;
    if (!isPlainObject(settings)) return null;
    for (const key of UNMODELLED_SETTINGS_KEYS) if (Object.hasOwn(settings, key)) return null;
  }
  if (!Object.hasOwn(parsed, "mcpServers")) return {};
  const servers = parsed.mcpServers;
  if (!isPlainObject(servers)) return null;
  const out = {};
  for (const name of Object.keys(servers)) {
    const def = servers[name];
    if (!isPlainObject(def)) return null;
    for (const key of Object.keys(def)) if (!KNOWN_SERVER_KEYS.has(key)) return null;
    if (Object.hasOwn(def, "socket")) return null;
    if (Object.hasOwn(def, "url") && typeof def.url !== "string") return null;
    if (Object.hasOwn(def, "command") && typeof def.command !== "string") return null;
    if (Object.hasOwn(def, "args") && !(Array.isArray(def.args) && def.args.every((a) => typeof a === "string"))) {
      return null;
    }
    Object.defineProperty(out, name, { value: def, enumerable: true, writable: true, configurable: true });
  }
  return out;
}
function readMcpServerView(sources) {
  try {
    if (sources === void 0) return void 0;
    const merged = /* @__PURE__ */ new Map();
    for (const path of sources) {
      const read = readSource(path);
      if (read.kind === "absent") continue;
      if (read.kind === "failed") return void 0;
      const servers = modelledServers(read.text);
      if (servers === null) return void 0;
      if (servers === "empty") continue;
      for (const name of Object.keys(servers)) {
        const def = servers[name];
        const base = { ...merged.get(name) ?? {} };
        if (typeof def.command === "string") delete base.url;
        else if (typeof def.url === "string") {
          delete base.command;
          delete base.args;
        }
        if (typeof def.url === "string") base.url = def.url;
        if (typeof def.command === "string") base.command = def.command;
        if (Array.isArray(def.args)) base.args = [...def.args];
        if (typeof def.type === "string") base.type = def.type;
        merged.set(name, base);
      }
    }
    return merged;
  } catch {
    return void 0;
  }
}
function projectServerConfig(view, serverName) {
  try {
    if (view === void 0 || typeof serverName !== "string" || serverName === "") return void 0;
    if (serverName.includes("__")) return void 0;
    const def = view.get(serverName);
    if (def === void 0) return void 0;
    const hasUrl = typeof def.url === "string" && def.url !== "";
    const hasCommand = typeof def.command === "string" && def.command !== "";
    if (hasUrl === hasCommand) return void 0;
    if (hasUrl) return typeof def.type === "string" ? { url: def.url, type: def.type } : { url: def.url };
    const out = { command: def.command };
    if (Array.isArray(def.args)) out.args = [...def.args];
    if (typeof def.type === "string") out.type = def.type;
    return out;
  } catch {
    return void 0;
  }
}
function signatureOf(paths) {
  const parts = [];
  for (const path of paths) {
    let part = `${path}=`;
    for (const stat of [lstatSync2, statSync]) {
      try {
        const s = stat(path);
        part += `${s.dev}:${s.ino}:${s.size}:${s.mtimeMs}:${s.ctimeMs};`;
      } catch {
        part += "-;";
      }
    }
    parts.push(part);
  }
  return parts.join("|");
}
function createMcpConfigReader(options) {
  let snap;
  let invalidated = false;
  function take(cwd) {
    const safeCwd2 = typeof cwd === "string" ? cwd : "";
    const sources = mcpConfigSources(options, safeCwd2);
    if (sources === void 0) return false;
    const signature = signatureOf(sources);
    const view = readMcpServerView(sources);
    if (signatureOf(sources) !== signature) invalidated = true;
    snap = { cwd: safeCwd2, sources, signature, view };
    return true;
  }
  return {
    snapshot(cwd) {
      try {
        if (snap === void 0) take(cwd);
      } catch {
      }
    },
    serverConfig(serverName, cwd) {
      try {
        if (snap === void 0 && !take(cwd)) return void 0;
        if (invalidated || snap === void 0 || snap.view === void 0) return void 0;
        if (signatureOf(snap.sources) !== snap.signature) {
          invalidated = true;
          return void 0;
        }
        if (cwd !== snap.cwd) return void 0;
        return projectServerConfig(snap.view, serverName);
      } catch {
        return void 0;
      }
    }
  };
}

// packages/pi/src/prompt.ts
async function decideInput(event, ctx, deps) {
  try {
    if (event.source === "extension") return void 0;
    const text = typeof event.text === "string" ? event.text : "";
    if (text.trim() === "") return void 0;
    const payload = buildPromptPayload({
      prompt: text,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      hasUI: ctx.hasUI,
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    });
    const hooks = deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, "user_prompt", hooks);
    switch (outcome.kind) {
      case "deny": {
        const reason = outcome.reason;
        notifySafe(ctx, reason === void 0 ? GENERIC_DENY_REASON : DENY_PREFIX + reason, "error");
        return { action: "handled" };
      }
      case "unavailable":
        notifySafe(ctx, outcome.reason ?? ENGINE_UNAVAILABLE_REASON, "error");
        return { action: "handled" };
      case "confirm":
        notifySafe(ctx, outcome.reason ?? GENERIC_DENY_REASON, "warning");
        noteSafe(() => deps.onPrompt?.(text));
        return void 0;
      case "allow":
        noteSafe(() => deps.onPrompt?.(text));
        return void 0;
      default:
        return void 0;
    }
  } catch {
    return void 0;
  }
}

// packages/pi/src/toolResult.ts
function recordToolResult(event, store, redact) {
  try {
    const content = Array.isArray(event?.content) ? event.content : [];
    const hashed = hashContent(content);
    const captured = captureText(content, MAX_TOOL_OUTPUT_CHARS, redact);
    store.recordResult({
      tool_name: typeof event?.toolName === "string" ? event.toolName : "",
      tool_use_id: typeof event?.toolCallId === "string" ? event.toolCallId : "",
      is_error: event?.isError === true,
      ...hashed.content_sha256 === void 0 ? {} : { content_sha256: hashed.content_sha256 },
      content_bytes: hashed.content_bytes,
      ...hashed.hash_skipped === true ? { hash_skipped: true } : {},
      ...captured === void 0 ? {} : { content: captured.text },
      ...captured?.truncated === true ? { content_truncated: true } : {},
      ...captured?.original_chars === void 0 ? {} : { content_original_chars: captured.original_chars }
    });
  } catch {
  }
  return void 0;
}

// packages/pi/src/userBash.ts
import { randomBytes as randomBytes3 } from "node:crypto";

// packages/pi/src/bashResult.ts
function denyBashResult(output) {
  return { result: { output, exitCode: 1, cancelled: false, truncated: false } };
}

// packages/pi/src/userBash.ts
function newUserBashId() {
  return USER_BASH_ID_PREFIX + randomBytes3(10).toString("hex");
}
async function decideUserBash(event, ctx, deps) {
  try {
    const command = typeof event.command === "string" ? event.command : "";
    if (command.trim() === "") return void 0;
    const toolUseId = newUserBashId();
    const payload = buildPretoolPayload({
      // A user-typed command IS a bash command; Phase 7 registered the lowercase name.
      toolName: "bash",
      command,
      toolUseId,
      // Empty by construction: there is no model-produced input here, so the allowlist has nothing
      // to forward and no file body can ride along.
      toolInput: {},
      cwd: event.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity }
    });
    const hooks = deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, "bash", hooks);
    noteDecision(deps, {
      tool_name: "bash",
      tool_use_id: toolUseId,
      decision: outcome.kind,
      // `{}` in, so the only key out is the capped `command` — which is the entire content of a
      // `!cmd`, and what the audit row would otherwise have described as an unnamed bash call.
      tool_input: auditToolInput({}, command)
    });
    switch (outcome.kind) {
      case "allow":
        return void 0;
      case "deny": {
        const reason = outcome.reason;
        notifySafe(ctx, reason ?? GENERIC_DENY_REASON, "error");
        return denyBashResult(reason === void 0 ? GENERIC_DENY_REASON : DENY_PREFIX + reason);
      }
      case "confirm": {
        if (!ctx.hasUI) return denyBashResult(NO_UI_REASON);
        const reason = outcome.reason ?? GENERIC_DENY_REASON;
        notifySafe(ctx, reason, "warning");
        const accepted = await confirmWithTimeout(ctx, CONFIRM_TITLE, CONFIRM_QUESTION);
        return accepted ? void 0 : denyBashResult(DECLINED_REASON);
      }
      case "unavailable":
        return denyBashResult(outcome.reason ?? ENGINE_UNAVAILABLE_REASON);
      default:
        return void 0;
    }
  } catch {
    return void 0;
  }
}

// packages/pi/src/index.ts
function sessionIdOf(ctx) {
  try {
    const id = ctx.sessionManager.getSessionId();
    return typeof id === "string" ? id : "";
  } catch {
    return "";
  }
}
function safeCwd(ctx) {
  try {
    return typeof ctx.cwd === "string" ? ctx.cwd : "";
  } catch {
    return "";
  }
}
function modelProviderOf(ctx) {
  try {
    const provider = ctx.model?.provider;
    return typeof provider === "string" && provider.length > 0 ? provider : void 0;
  } catch {
    return void 0;
  }
}
function versionOf(entrypoint) {
  const slash = entrypoint.indexOf("/");
  return slash === -1 ? entrypoint : entrypoint.slice(slash + 1);
}
var processHeartbeatGate = createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS });
function makeCacheSync(apiKey, baseUrl, env = {}, homeDir = "") {
  const cachePath = resolveCachePath(env, homeDir);
  if (cachePath === void 0) return void 0;
  const fingerprint = keyFingerprint(apiKey);
  return (snapshot2) => {
    void writeCache(cachePath, {
      ...snapshot2,
      gateway_url: baseUrl,
      key_fingerprint: fingerprint
    });
  };
}
function defaultMakeChecker(apiKey, baseUrl, env = {}, homeDir = "") {
  const client = createApiClient({ baseUrl, apiKey });
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
    breaker: createBreaker({ now: Date.now }),
    keyState,
    onSync: makeCacheSync(apiKey, baseUrl, env, homeDir)
  });
}
function hydrateFromCache(apiKey, baseUrl, env, homeDir) {
  try {
    const cachePath = resolveCachePath(env, homeDir);
    if (cachePath === void 0) return;
    const onDisk = readCache(cachePath, { gatewayUrl: baseUrl, fingerprint: keyFingerprint(apiKey) });
    if (onDisk !== void 0) policyState.hydrate(onDisk);
  } catch {
  }
}
function safeHomeDir() {
  try {
    return homedir();
  } catch {
    return "";
  }
}
function createExtension(overrides = {}) {
  const env = overrides.env ?? process.env;
  const homeDir = overrides.homeDir ?? safeHomeDir();
  const deps = {
    env,
    homeDir,
    // The cache path is resolved from the same env/home pair the key came from, so a test with a
    // temp HOME cannot accidentally read or write the developer's real cache.
    makeChecker: overrides.makeChecker ?? ((apiKey, baseUrl) => defaultMakeChecker(apiKey, baseUrl, env, homeDir)),
    entrypoint: overrides.entrypoint,
    heartbeatGate: overrides.heartbeatGate ?? processHeartbeatGate,
    identity: overrides.identity ?? {},
    argv: overrides.argv ?? process.argv
  };
  const identityLoader = createAccountIdentityLoader({
    ...deps.identity,
    agentDir: resolvePiAgentDir(env, homeDir)
  });
  function identityOption() {
    try {
      const identity = identityLoader.current();
      return identity === void 0 ? {} : { accountIdentity: identity };
    } catch {
      return {};
    }
  }
  const mcpConfigReader = createMcpConfigReader({ env, homeDir, argv: deps.argv });
  const inflight = createInflightCalls(MAX_INFLIGHT_MCP_CALLS, MCP_INFLIGHT_MAX_AGE_MS);
  let lastCtx;
  const seeCtx = (ctx) => {
    if (ctx !== null && typeof ctx === "object") lastCtx = ctx;
  };
  let resolved;
  let notified = false;
  function init() {
    if (resolved === void 0) {
      const apiKey = resolveApiKey(deps.env, deps.homeDir);
      const baseUrl = apiKey === void 0 ? void 0 : resolveGatewayUrl(deps.env, deps.homeDir);
      if (apiKey !== void 0 && baseUrl !== void 0) {
        hydrateFromCache(apiKey, baseUrl, deps.env, deps.homeDir);
      }
      const inactive = apiKey === void 0 || baseUrl === void 0;
      const client = inactive ? void 0 : createApiClient({ baseUrl, apiKey });
      resolved = {
        apiKey,
        entrypoint: deps.entrypoint ?? resolveClientEntrypoint(deps.env, process.argv[1]),
        checker: inactive ? void 0 : deps.makeChecker(apiKey, baseUrl),
        client,
        telemetry: client === void 0 ? void 0 : createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
        cacheSync: inactive ? void 0 : makeCacheSync(apiKey, baseUrl, deps.env, deps.homeDir)
      };
    }
    return resolved;
  }
  function recordingActive(state) {
    return state.apiKey !== void 0 && state.client !== void 0 && !keyState.isInactive();
  }
  function modelIdOf(ctx) {
    try {
      const id = ctx?.model?.id;
      return typeof id === "string" ? id : void 0;
    } catch {
      return void 0;
    }
  }
  function brokerActive() {
    try {
      const state = init();
      return recordingActive(state) && state.checker !== void 0;
    } catch {
      return false;
    }
  }
  async function decideBrokered(call) {
    const state = init();
    if (!recordingActive(state) || state.checker === void 0) return "abstain";
    const ctx = lastCtx;
    const sessionId = ctx === void 0 ? "" : sessionIdOf(ctx);
    const cwd = ctx === void 0 ? "" : safeCwd(ctx);
    const matchedId = inflight.claim(call.serverName, call.prefixedToolName, call.originalToolName, call.args);
    const toolUseId = matchedId ?? mintBrokerId();
    const serverConfig = mcpConfigReader.serverConfig(call.serverName, cwd);
    return decideMcpApproval(
      {
        call: {
          server: call.serverName,
          tool: call.originalToolName,
          args: call.args,
          ...call.origin === "" ? {} : { origin: call.origin },
          ...serverConfig === void 0 ? {} : { serverConfig }
        },
        toolUseId,
        cwd,
        sessionId,
        model: modelIdOf(ctx),
        ui: ctx,
        ...call.signal === void 0 ? {} : { signal: call.signal }
      },
      {
        checker: state.checker,
        apiKey: state.apiKey,
        entrypoint: state.entrypoint,
        ...identityOption(),
        currentPrompt: () => turnStore.currentPrompt(sessionId),
        onDecision: (entry) => {
          if (!recordingActive(state)) return;
          if (matchedId !== void 0) {
            turnStore.recordToolCall(entry, sessionId);
            return;
          }
          postStandaloneTurn(entry, { cwd }, sessionId, {
            client: state.client,
            apiKey: state.apiKey,
            ...state.telemetry === void 0 ? {} : { telemetry: state.telemetry },
            ...identityOption()
          });
        }
      }
    );
  }
  function brokerPreempted() {
    try {
      const state = init();
      if (!recordingActive(state)) return;
      state.telemetry?.reportBypass({
        errorClass: "McpBrokerPreempted",
        toolName: "mcp_broker",
        elapsedMs: 0,
        blocked: false
      });
    } catch {
    }
  }
  return (pi) => {
    try {
      const events = pi.events;
      if (events !== null && typeof events === "object" && typeof events.on === "function") {
        events.on.call(
          events,
          MCP_TOOL_APPROVAL_REQUEST_EVENT,
          createMcpApprovalListener({ active: brokerActive, decide: decideBrokered, preempted: brokerPreempted })
        );
      }
    } catch {
    }
    pi.on("session_start", async (_event, ctx) => {
      try {
        turnStore.reset(sessionIdOf(ctx));
        inflight.keepSession(sessionIdOf(ctx));
        seeCtx(ctx);
        const state = init();
        if (state.apiKey === void 0 && !notified) {
          notified = true;
          notifySafe(ctx, NO_KEY_NOTICE, "info");
        }
        if (state.apiKey === void 0 || state.client === void 0) return void 0;
        if (keyState.isInactive()) return void 0;
        mcpConfigReader.snapshot(safeCwd(ctx));
        const identityPending = identityLoader.start(modelProviderOf(ctx));
        if (!deps.heartbeatGate.shouldSend(policyState.getFetchedAt())) return void 0;
        deps.heartbeatGate.markSent();
        const heartbeatInput = {
          cwd: safeCwd(ctx),
          sessionId: sessionIdOf(ctx),
          model: ctx.model?.id,
          clientEntrypoint: state.entrypoint,
          hasUI: ctx.hasUI === true,
          piVersion: versionOf(state.entrypoint)
        };
        const client = state.client;
        void identityPending.then(
          (identity) => client.postPretool(
            buildHeartbeatPayload({
              ...heartbeatInput,
              ...identity === void 0 ? {} : { accountIdentity: identity }
            })
          )
        ).then((result) => {
          if (!result.ok) return;
          policyState.recordSuccess(result.body);
          try {
            state.cacheSync?.(policyState.snapshot());
          } catch {
          }
        }).catch(() => {
        });
        if (SESSION_PRESENCE_ROW_ENABLED) {
          void client.postTurnLog(
            buildTurnLogBody(
              { tool_calls: [], results: [], session_id: sessionIdOf(ctx), started_at: Date.now() },
              { cwd: safeCwd(ctx), completedAtMs: Date.now() }
            )
          ).catch(() => {
          });
        }
      } catch {
      }
      return void 0;
    });
    pi.on("tool_call", async (event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === void 0 || state.checker === void 0) return void 0;
        seeCtx(ctx);
        if (recordingActive(state) && !isShellCall(event) && !NATIVE_FILE_TOOLS.has(event.toolName)) {
          inflight.remember(
            { toolCallId: event.toolCallId, toolName: event.toolName, input: event.input },
            sessionIdOf(ctx)
          );
        }
        return await decideToolCall(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          // Bound to the LIVE ctx at the registration, so 09-02's breaker-open and key-rejected
          // notices — raised deep inside `checkTool` — actually reach the editor on this path.
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The pretool `messages[0].content`, which the gateway writes its block/warn row from. A
          // cheap getter, not `snapshot()`: this runs on every evaluated tool call.
          currentPrompt: () => turnStore.currentPrompt(sessionIdOf(ctx)),
          // Re-checked here rather than above: `checkTool` may have latched the key on this very
          // call, and the turn that latched is one nothing will post.
          onDecision: (entry) => {
            if (recordingActive(state)) turnStore.recordToolCall(entry, sessionIdOf(ctx));
          }
        });
      } catch {
        return void 0;
      }
    });
    pi.on("tool_result", async (event, ctx) => {
      try {
        seeCtx(ctx);
        inflight.forget(event?.toolCallId);
        if (!recordingActive(init())) return void 0;
        const apiKey = init().apiKey;
        recordToolResult(event, turnStore, (text) => redactSecrets(text, apiKey));
      } catch {
      }
      return void 0;
    });
    pi.on("agent_end", (event, ctx) => {
      try {
        const state = init();
        if (!recordingActive(state)) {
          turnStore.take();
          return void 0;
        }
        return handleAgentEnd(event, ctx, {
          client: state.client,
          store: turnStore,
          ...state.apiKey === void 0 ? {} : { apiKey: state.apiKey },
          ...state.telemetry === void 0 ? {} : { telemetry: state.telemetry },
          ...identityOption()
        });
      } catch {
        return void 0;
      }
    });
    pi.on("user_bash", async (event, ctx) => {
      try {
        const state = init();
        seeCtx(ctx);
        if (state.apiKey === void 0 || state.checker === void 0) return void 0;
        return await decideUserBash(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // Posted as its OWN one-call turn log, immediately, and never written into `turnStore`:
          // pi fires no `agent_end` for a `!cmd`, so a stored entry waited for the next agent turn
          // and was posted under that turn's prompt. Fire-and-forget — this handler is awaited, and
          // `postStandaloneTurn` returns before the POST settles. `recordingActive` is re-checked
          // here for the same reason as on `tool_call`: this very call may have latched the key.
          onDecision: (entry) => {
            if (recordingActive(state)) {
              postStandaloneTurn(entry, ctx, sessionIdOf(ctx), {
                client: state.client,
                apiKey: state.apiKey,
                ...state.telemetry === void 0 ? {} : { telemetry: state.telemetry },
                ...identityOption()
              });
            }
          }
        });
      } catch {
        return void 0;
      }
    });
    pi.on("input", async (event, ctx) => {
      try {
        const state = init();
        seeCtx(ctx);
        if (state.apiKey === void 0 || state.checker === void 0) return void 0;
        return await decideInput(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The turn log's only source for the prompt: `agent_end.messages` is pi's `newMessages`
          // and never contains it (§A4). Called for an ALLOWED prompt only — a suppressed turn
          // produced nothing to log.
          onPrompt: (text) => {
            if (recordingActive(state)) turnStore.recordPrompt(text, sessionIdOf(ctx));
          }
        });
      } catch {
        return void 0;
      }
    });
  };
}
var index_default = createExtension();
export {
  createExtension,
  index_default as default,
  defaultMakeChecker,
  makeCacheSync
};
