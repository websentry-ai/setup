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
import { homedir as homedir2 } from "node:os";

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
  const run2 = opts.execFile ?? defaultExecFile;
  const exec = (file, args) => attempt(() => run2(file, args, { timeoutMs, maxBytes: MAX_SERIAL_PROBE_BYTES })).catch(() => void 0);
  const platform = opts.platform ?? process.platform;
  if (platform === "darwin") {
    const out = await exec(probeToolPath("system_profiler"), ["SPHardwareDataType"]);
    for (const line of (out ?? "").split("\n")) {
      if (!line.includes("Serial Number")) continue;
      const sep2 = line.indexOf(": ");
      if (sep2 === -1) continue;
      const value = line.slice(sep2 + 2);
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
    hydrate(snapshot3) {
      if (snapshot3 === null || typeof snapshot3 !== "object" || Array.isArray(snapshot3)) return;
      if (toolsSyncedAt === void 0) {
        const tools = parseToolsToCheck(snapshot3.tools_to_check);
        const syncedAt = parseTimestamp(snapshot3.tools_synced_at);
        if (tools !== void 0 && syncedAt !== void 0) {
          toolsToCheck = tools;
          toolsSyncedAt = syncedAt;
        }
      }
      if (fetchedAt === void 0) {
        const action = parseFailureAction(snapshot3.policy_check_failure_action);
        if (action !== void 0) failureAction = action;
        const fetched = parseTimestamp(snapshot3.fetched_at);
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
function capCommand(command2, maxChars = MAX_COMMAND_CHARS) {
  if (command2.length <= maxChars) return { command: command2, truncated: false };
  const budget = maxChars - COMMAND_TRUNCATION_MARKER.length;
  if (budget <= 1) return { command: command2.slice(0, maxChars), truncated: true };
  const headChars = Math.ceil(budget / 2);
  const tailChars = budget - headChars;
  return {
    command: command2.slice(0, headChars) + COMMAND_TRUNCATION_MARKER + command2.slice(-tailChars),
    truncated: true
  };
}
function auditToolInput(toolInput, command2) {
  const isObject = toolInput !== null && typeof toolInput === "object" && !Array.isArray(toolInput);
  const source = isObject ? { ...toolInput } : {};
  delete source.command;
  const out = sanitizeToolInput(source);
  if (typeof command2 === "string" && command2 !== "") out.command = capCommand(command2).command;
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
    if (mcp.serverConfig !== void 0) metadata.mcp_server_config = mcp.serverConfig;
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
function isoSeconds(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return void 0;
  try {
    return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
  } catch {
    return void 0;
  }
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
    toolUse = calls.map((call) => {
      const toolUseId = typeof call?.tool_use_id === "string" ? call.tool_use_id : "";
      const entry = {
        type: TURNLOG_TOOL_USE_TYPE,
        tool_name: typeof call?.tool_name === "string" ? call.tool_name : "",
        tool_use_id: toolUseId,
        // `call`-derived, and still never `event.input`-derived: what the record holds was already
        // allowlisted and capped by `auditToolInput` — header decision 2.
        tool_input: toolInputFor(call?.tool_input, opts?.apiKey),
        tool_response: toolResponseFor(safe, toolUseId, opts?.apiKey)
      };
      const ts = isoSeconds(call?.ts);
      if (ts !== void 0) entry.ts = ts;
      const transfer = toolUseId === "" ? void 0 : opts?.transfers?.get(toolUseId);
      if (transfer !== void 0) entry.transfer = transfer;
      return entry;
    });
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
    markNotRun(toolUseId) {
      try {
        for (const call of record.tool_calls) if (call.tool_use_id === toolUseId) call.ran = false;
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
      const copy2 = {
        // `tool_input` is copied a second time so `snapshot()` never hands callers a live reference
        // into the record. A native call's values are scalars (`sanitizeToolInput` forwards nothing
        // else), but an MCP call's capped arguments can nest, so the copy is structural.
        tool_calls: record.tool_calls.map(
          (entry) => entry.tool_input === void 0 ? { ...entry } : { ...entry, tool_input: copyInput(entry.tool_input) }
        ),
        results: record.results.map((entry) => ({ ...entry }))
      };
      if (record.prompt !== void 0) copy2.prompt = record.prompt;
      if (record.session_id !== void 0) copy2.session_id = record.session_id;
      if (record.started_at !== void 0) copy2.started_at = record.started_at;
      if (record.results_truncated !== void 0) copy2.results_truncated = record.results_truncated;
      if (record.tool_calls_truncated !== void 0) {
        copy2.tool_calls_truncated = record.tool_calls_truncated;
      }
      return copy2;
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

// packages/core/src/transfer.ts
import { lookup as dnsLookup } from "node:dns/promises";
import { readdirSync, readFileSync as readFileSync3, realpathSync, statSync } from "node:fs";
import { BlockList, isIP } from "node:net";
import { homedir, userInfo } from "node:os";
import { basename, dirname as dirname3, isAbsolute as isAbsolute3, join as join5, normalize, sep } from "node:path";
var ALLOWED_RUNS = [["ssh", "-G"]];
var RUN_TIMEOUT_MS = 5e3;
var DNS_TIMEOUT_MS = 1500;
var TURN_BUDGET_MS = 1e4;
var MAX_OUTPUT_BYTES = 64 * 1024;
var MAX_ENDPOINTS = 10;
var MAX_DEPTH = 8;
var MAX_CALLS = 32;
var MAX_WORDS = 64;
var WRAPPERS = {
  sudo: {
    short: "ugCDhprtTU",
    long: "--user --group --close-from --chdir --host --prompt --role --type --command-timeout --other-user".split(" "),
    operands: 0
  },
  doas: { short: "uC", long: [], operands: 0 },
  env: { short: "uCS", long: ["--unset", "--chdir", "--split-string"], operands: 0 },
  nice: { short: "n", long: ["--adjustment"], operands: 0 },
  timeout: { short: "ks", long: ["--kill-after", "--signal"], operands: 1 },
  time: { short: "fo", long: ["--format", "--output"], operands: 0 },
  stdbuf: { short: "ioe", long: ["--input", "--output", "--error"], operands: 0 },
  ionice: { short: "cnp", long: ["--class", "--classdata", "--pid"], operands: 0 },
  exec: { short: "a", long: [], operands: 0 },
  command: { short: "", long: [], operands: 0 },
  builtin: { short: "", long: [], operands: 0 },
  nohup: { short: "", long: [], operands: 0 }
};
var WRAPPER_CHDIR = { env: ["-C", "--chdir"], sudo: ["-D", "--chdir"] };
var KEYWORDS = new Set(
  "{ } if then elif else fi while until for select do done ! function".split(" ")
);
var LEADING_WORDS = new Set("{ if then elif else while until do !".split(" "));
var LOOPS = ["while", "until", "for", "select"];
var DECLARES = ["declare", "typeset", "local", "readonly"];
var SHELLS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "dash", "ksh", "ash"]);
var POWERSHELLS = /* @__PURE__ */ new Set(["powershell", "pwsh"]);
var CLEAN_ENV = "\0clean";
var SUBSTITUTED = "\0";
var BRACE_MARKS = { "{": "", ",": "", "}": "" };
function unmark(word) {
  return word.replace(/[\x01-\x03]/g, (mark) => "{,}"[mark.charCodeAt(0) - 1]);
}
var TOOLS = {
  curl: "curl",
  wget: "wget",
  scp: "scp",
  rsync: "rsync",
  sftp: "sftp",
  ssh: "ssh",
  nc: "nc",
  ncat: "nc",
  netcat: "nc",
  socat: "socat",
  http: "httpie",
  https: "httpie",
  "invoke-webrequest": "powershell",
  "invoke-restmethod": "powershell",
  iwr: "powershell",
  irm: "powershell"
};
var SENDING_METHODS = /* @__PURE__ */ new Set(["POST", "PUT", "PATCH"]);
var DEFAULT_PORTS = { http: 80, https: 443, ftp: 21, ftps: 990, ws: 80, wss: 443 };
var SSH_VALUE_FLAGS = {
  ssh: "BbcDEeFIiJLlmOoPpQRSWw",
  scp: "cDFiJloPSX",
  sftp: "BbcDFiJloPRSsX",
  rsync: "efTMB@"
};
var SSH_IDENTITY_OPTIONS = /* @__PURE__ */ new Set(["hostname", "user", "port", "proxyjump"]);
var SSH_CONFIG_MAX_BYTES = 256 * 1024;
var SSH_CONFIG_MAX_FILES = 32;
var RSYNC_VALUE_OPTIONS = new Set(
  `--exclude --include --filter --exclude-from --include-from --files-from --rsync-path --log-file --partial-dir
   --temp-dir --compare-dest --copy-dest --link-dest --backup-dir --chmod --chown --suffix --password-file --port
   --bwlimit --timeout --max-size --min-size --out-format --remote-option --block-size --modify-window`.split(/\s+/)
);
var CURL_SHORT_VALUES = "ACDEFHKPQTUXYbcdemortuwxyz";
var CURL_LONG_VALUES = new Set(
  `--abstract-unix-socket --alt-svc --aws-sigv4 --cacert --capath --cert --cert-type --ciphers --config
   --connect-timeout --connect-to --continue-at --cookie --cookie-jar --create-file-mode --crlfile --curves --data
   --data-ascii --data-binary --data-raw --data-urlencode --delegation --dns-interface --dns-ipv4-addr
   --dns-ipv6-addr --dns-servers --doh-url --dump-header --egd-file --engine --etag-compare --etag-save
   --expect100-timeout --form --form-string --ftp-account --ftp-alternative-to-user --ftp-method --ftp-port
   --ftp-ssl-ccc-mode --happy-eyeballs-timeout-ms --haproxy-clientip --header --hostpubmd5 --hostpubsha256 --hsts
   --interface --ipfs-gateway --json --keepalive-time --key --key-type --krb --libcurl --limit-rate --local-port
   --login-options --mail-auth --mail-from --mail-rcpt --max-filesize --max-redirs --max-time --netrc-file
   --noproxy --oauth2-bearer --output --output-dir --parallel-max --pass --pinnedpubkey --preproxy --proto
   --proto-default --proto-redir --proxy --proxy-cacert --proxy-capath --proxy-cert --proxy-cert-type
   --proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass --proxy-pinnedpubkey
   --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype --proxy-tlspassword --proxy-tlsuser --proxy-user
   --pubkey --quote --random-file --range --rate --referer --request --request-target --resolve --retry
   --retry-delay --retry-max-time --sasl-authzid --service-name --socks4 --socks4a --socks5
   --socks5-gssapi-service --socks5-hostname --speed-limit --speed-time --stderr --telnet-option --tftp-blksize
   --time-cond --tls-max --tls13-ciphers --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii
   --trace-config --unix-socket --upload-file --url --url-query --user --user-agent --variable --write-out`.split(/\s+/)
);
var CURL_UPLOADS = /* @__PURE__ */ new Set(["-T", "--upload-file", "-F", "--form", "--form-string", "--json"]);
var CURL_BODIES = /* @__PURE__ */ new Set(
  ["-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode"]
);
var WGET_SHORT_VALUES = "aABDeIilnOoPQRtTUwX";
var WGET_LONG_VALUES = new Set(
  `--output-file --append-output --execute --input-file --base --config --rejected-log --tries
   --retry-on-http-error --output-document --backups --timeout --dns-timeout --connect-timeout --read-timeout
   --wait --waitretry --bind-address --limit-rate --quota --user --password --header --compression --max-redirect
   --proxy-user --proxy-password --referer --save-cookies --load-cookies --post-data --post-file --method
   --body-data --body-file --default-page --directory-prefix --cut-dirs --level --accept --reject --accept-regex
   --reject-regex --regex-type --domains --exclude-domains --follow-tags --ignore-tags --include-directories
   --exclude-directories --user-agent --secure-protocol --certificate --certificate-type --private-key
   --private-key-type --ca-certificate --ca-directory --crl-file --pinnedpubkey --random-file --egd-file --ciphers
   --hsts-file --ftp-user --ftp-password --http-user --http-password --warc-file --warc-header --warc-max-size
   --warc-dedup --warc-tempdir --local-encoding --remote-encoding --restrict-file-names --prefer-family
   --report-speed --progress --use-askpass`.split(/\s+/)
);
var WGET_UPLOADS = /* @__PURE__ */ new Set(["--post-data", "--post-file", "--body-data", "--body-file"]);
var NC_SHORT_VALUES = "eGgIiMmOoPpqsTVWwXx";
var NC_LONG_VALUES = new Set(
  `--proxy --proxy-type --proxy-auth --proxy-dns --source --source-port --wait --idle-timeout --exec --sh-exec
   --lua-exec --output --hex-dump --allow --allowfile --deny --denyfile --max-conns --delay --ssl-cert --ssl-key
   --ssl-trustfile --ssl-ciphers --ssl-servername --ssl-alpn`.split(/\s+/)
);
var SOCAT_VALUE_OPTIONS = /* @__PURE__ */ new Set(["-b", "-t", "-T", "-L", "-W", "-lf", "-lp"]);
var HTTPIE_SHORT_VALUES = "aAoPps";
var HTTPIE_LONG_VALUES = new Set(
  `--auth --auth-type --session --session-read-only --output --print --history-print --pretty --style
   --format-options --response-charset --response-mime --verify --cert --cert-key --cert-key-pass --ssl --ciphers
   --timeout --max-redirects --max-headers --proxy --default-scheme --boundary --raw`.split(/\s+/)
);
var PS_SWITCHES = new Set(
  `usebasicparsing usedefaultcredentials proxyusedefaultcredentials disablekeepalive passthru skipcertificatecheck
   skipheadervalidation skiphttperrorcheck allowunencryptedauthentication allowinsecureredirect noproxy
   preserveauthorizationonredirect preservehttpmethodonredirect resume followrellink verbose debug whatif
   confirm`.split(/\s+/)
);
var ADDRESS_KINDS = [
  ["loopback", ["127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128"]],
  ["private", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]],
  ["link_local", ["169.254.0.0/16", "fe80::/10"]],
  ["cgnat", ["100.64.0.0/10"]]
];
async function run(argv, state) {
  try {
    if (!ALLOWED_RUNS.some((p) => p.every((part, i) => argv[i] === part))) return void 0;
    const remaining = state.deadline - state.now();
    if (remaining <= 0) return void 0;
    const [file, ...args] = argv;
    if (file === void 0) return void 0;
    return await state.run(file, args, { timeoutMs: Math.min(RUN_TIMEOUT_MS, remaining), maxBytes: MAX_OUTPUT_BYTES });
  } catch {
    return void 0;
  }
}
function wordEnd(text, start) {
  let i = start;
  while (i < text.length && (text[i] === " " || text[i] === "	")) i++;
  const bodies = [];
  let quote;
  for (; i < text.length; i++) {
    const ch = text[i];
    const at = i;
    if (quote === "'") {
      if (ch === "'") quote = void 0;
    } else if (ch === "\\") {
      i++;
    } else if (text.startsWith("$(", i) || ch === "`") {
      i = ch === "$" ? parenEnd(text, i + 2) : backtickEnd(text, i + 1);
      const inner = i > 0 && text.startsWith("$((", at) ? textBodies(text.slice(at + 3, i - 1)) : [];
      if (i < 0 || inner === void 0) return [-1, bodies];
      bodies.push(...text.startsWith("$((", at) ? inner : [ch === "$" ? text.slice(at + 2, i) : text.slice(at + 1, i)]);
    } else if (quote === '"') {
      if (ch === '"') quote = void 0;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (" 	\r\n;&|<>()".includes(ch)) {
      break;
    }
  }
  return [i, bodies];
}
function textBodies(body) {
  const bodies = [];
  for (let i = 0; i < body.length; i++) {
    const at = i;
    if (body[i] === "\\") {
      i++;
    } else if (body.startsWith("$(", i) || body[i] === "`") {
      i = body[i] === "$" ? parenEnd(body, i + 2) : backtickEnd(body, i + 1);
      const inner = i > 0 && body.startsWith("$((", at) ? textBodies(body.slice(at + 3, i - 1)) : [];
      if (i < 0 || inner === void 0) return void 0;
      bodies.push(...body.startsWith("$((", at) ? inner : [body[at] === "$" ? body.slice(at + 2, i) : body.slice(at + 1, i)]);
    }
  }
  return bodies;
}
function expanded(body) {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const at = i;
    if (body[i] === "\\" && ["$", "`", "\\", "\n"].includes(body[i + 1] ?? "")) {
      out += body[i + 1] === "\n" ? "" : body[i + 1];
      i++;
    } else if (body.startsWith("$(", i) || body[i] === "`") {
      i = body[i] === "$" ? parenEnd(body, i + 2) : backtickEnd(body, i + 1);
      if (i < 0) return body.slice(0, at) + SUBSTITUTED;
      out += SUBSTITUTED;
    } else {
      out += body[i];
    }
  }
  return out;
}
function readWord(text, start) {
  let i = start;
  while (i < text.length && (text[i] === " " || text[i] === "	")) i++;
  let word = "";
  let quote;
  for (; i < text.length; i++) {
    const ch = text[i];
    if (quote !== void 0) {
      if (ch === quote) quote = void 0;
      else if (ch === "\\" && quote === '"' && i + 1 < text.length) word += text[++i];
      else word += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "\\" && i + 1 < text.length) {
      word += text[++i];
    } else if (" 	\r\n;&|<>()".includes(ch)) {
      break;
    } else {
      word += ch;
    }
  }
  return [word, i];
}
function parenEnd(text, start) {
  let depth = 1;
  let quote;
  const cases = [];
  const heredocs = [];
  let word = "";
  let atStart = true;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (quote === "'") {
      if (ch === "'") quote = void 0;
    } else if (quote === void 0 && ch === "#" && word === "") {
      i = text.indexOf("\n", i) - 1;
      if (i < 0) return -1;
    } else if (quote === void 0 && text.startsWith("<<", i) && !text.startsWith("<<<", i)) {
      const strip = text.startsWith("<<-", i);
      const [delimiter, end2] = readWord(text, i + (strip ? 3 : 2));
      heredocs.push([delimiter, strip]);
      i = end2 - 1;
    } else if (ch === "\\") {
      i++;
      word += "\0";
    } else if (quote === '"') {
      if (ch === '"') quote = void 0;
      else if (text.startsWith("$(", i)) {
        i = parenEnd(text, i + 2);
        if (i < 0) return -1;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      word += "\0";
    } else if (!" 	\r\n;&|()<>".includes(ch)) {
      word += ch;
    } else {
      if (word !== "") atStart = caseWord(word, atStart, cases);
      word = "";
      if (cases.at(-1) === "pattern" && (ch === "(" || ch === ")")) {
        if (ch === ")") [cases[cases.length - 1], atStart] = ["body", true];
      } else if (ch === "(" || ch === ")") {
        depth += ch === "(" ? 1 : -1;
        if (depth === 0) return i;
      }
      if (";&|\n(".includes(ch)) atStart = true;
      if (cases.at(-1) === "body" && (text.startsWith(";;", i) || text.startsWith(";&", i))) {
        cases[cases.length - 1] = "pattern";
        i += text.startsWith(";;&", i) ? 2 : 1;
      }
      if (ch === "\n") i = heredocsEnd(text, i, heredocs);
    }
  }
  return -1;
}
function heredocsEnd(text, start, heredocs) {
  let i = start;
  while (heredocs.length > 0) {
    const [delimiter, stripTabs] = heredocs.shift();
    while (i + 1 < text.length) {
      const end2 = text.indexOf("\n", i + 1);
      const line = end2 < 0 ? text.slice(i + 1) : text.slice(i + 1, end2);
      i = end2 < 0 ? text.length - 1 : end2;
      if ((stripTabs ? line.replace(/^\t+/, "") : line) === delimiter) break;
    }
  }
  return i;
}
function caseWord(word, atStart, cases) {
  if (word === "case" && atStart) cases.push("head");
  else if (word === "in" && cases.at(-1) === "head") cases[cases.length - 1] = "pattern";
  else if (word === "esac" && cases.length > 0 && cases.at(-1) !== "head") cases.pop();
  else return LEADING_WORDS.has(word);
  return false;
}
function arithmeticParts(text) {
  const parts = [];
  let begin2 = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.startsWith("$(", i) || text[i] === "`") {
      i = text[i] === "$" ? parenEnd(text, i + 2) : backtickEnd(text, i + 1);
      if (i < 0) return void 0;
    } else if (text[i] === ";") {
      parts.push(text.slice(begin2, i));
      begin2 = i + 1;
    }
  }
  return parts.length === 2 ? [...parts, text.slice(begin2)] : void 0;
}
function backtickEnd(text, start) {
  for (let i = start; i < text.length; i += text[i] === "\\" ? 2 : 1) if (text[i] === "`") return i;
  return -1;
}
var Lexer = class _Lexer {
  i = 0;
  quote;
  items = [];
  argv = [];
  word = "";
  inWord = false;
  before = "";
  io = [];
  /** Each heredoc still to read: its delimiter, whether tabs are stripped, where an unquoted one's substitutions go,
   *  and where its text goes. */
  heredocs = [];
  failed = false;
  /** Where in the text each simple command ends. */
  ends = /* @__PURE__ */ new Map();
  cases = [];
  text;
  depth;
  /** How deep the reader is inside a ${…} parameter, and where the word's last unquoted $ is. */
  param = 0;
  dollar = -1;
  constructor(text, depth = 0) {
    this.text = text;
    this.depth = depth;
  }
  /** The items, or undefined when the command can't be read the way the shell reads it. */
  read() {
    if (this.depth > MAX_DEPTH) return void 0;
    for (; this.i < this.text.length; this.i++) {
      if (!(this.quote !== void 0 ? this.quoted() : this.unquoted()) || this.failed) return void 0;
    }
    if (this.quote !== void 0) return void 0;
    this.endCommand("");
    return this.failed ? void 0 : this.items;
  }
  marker(kind, before = "", argv = []) {
    this.items.push({ kind, argv, before, after: "", io: [] });
  }
  quoted() {
    const ch = this.text[this.i];
    if (ch === this.quote) {
      this.quote = void 0;
    } else if (this.quote === '"' && (ch === "$" || ch === "`")) {
      const found = this.substitution();
      if (found !== void 0) return found;
      this.word += ch;
    } else if (this.quote === '"' && ch === "\\" && this.i + 1 < this.text.length) {
      this.word += this.text[++this.i];
    } else {
      this.word += ch;
    }
    return true;
  }
  unquoted() {
    const { text, i } = this;
    const ch = text[i];
    if ("$`<>".includes(ch)) {
      const found = this.substitution();
      if (found !== void 0) return found;
    }
    if (ch === "'" || ch === '"') {
      this.quote = ch;
      this.inWord = true;
    } else if (ch === "\\" && text[i + 1] === "\n") {
      this.i++;
    } else if (ch === "\\" && i + 1 < text.length) {
      this.word += text[++this.i];
      this.inWord = true;
    } else if (ch === "#" && !this.inWord) {
      const end2 = text.indexOf("\n", i);
      this.i = (end2 < 0 ? text.length : end2) - 1;
    } else if (ch === "(") {
      this.open();
    } else if (ch === ")") {
      this.close();
    } else if (ch === "<" || ch === ">" || text.startsWith("&>", i)) {
      this.redirect();
    } else if (";&|\n".includes(ch)) {
      this.separator(ch);
    } else if (ch === " " || ch === "	" || ch === "\r") {
      this.endWord();
    } else {
      this.word += this.mark(ch);
      this.inWord = true;
    }
    return true;
  }
  /** An unquoted character as it goes into the word: a { , or } bash may brace-expand is marked, unless it is part
   *  of a ${…} parameter. */
  mark(ch) {
    if (ch === "{" && (this.param > 0 || this.dollar >= 0 && this.dollar === this.word.length - 1)) this.param++;
    else if (ch === "}" && this.param > 0) this.param--;
    else if (ch === "$") this.dollar = this.word.length;
    else if (this.param === 0) return BRACE_MARKS[ch] ?? ch;
    return ch;
  }
  /** Read a $( ), $(( )), backtick or <( ) substitution starting here; undefined when none starts here. */
  substitution() {
    const { text, i } = this;
    let end2;
    let inner;
    if (text.startsWith("$((", i)) {
      end2 = parenEnd(text, i + 2);
      const bodies = end2 > 0 ? textBodies(text.slice(i + 3, end2 - 1)) : void 0;
      if (bodies === void 0) return false;
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : void 0);
    } else if (text.startsWith("$(", i) || this.quote === void 0 && (text.startsWith("<(", i) || text.startsWith(">(", i))) {
      end2 = parenEnd(text, i + 2);
      inner = text.slice(i + 2, end2);
    } else if (text[i] === "`") {
      end2 = backtickEnd(text, i + 1);
      if (end2 < 0) return void 0;
      inner = text.slice(i + 1, end2);
    } else {
      return void 0;
    }
    if (end2 < 0) return false;
    if (inner !== void 0) {
      const items = new _Lexer(inner, this.depth + 1).read();
      if (items === void 0) return false;
      this.flushLeading();
      this.marker("$(", this.before);
      this.items.push(...items);
      this.marker(")");
    }
    this.word += SUBSTITUTED;
    this.inWord = true;
    this.i = end2;
    return true;
  }
  open() {
    if (this.cases.at(-1) === "pattern") return;
    const lead = this.argv.at(-1) === "for" ? this.argv.slice(0, -1) : this.argv;
    const close = this.text.startsWith("((", this.i) ? parenEnd(this.text, this.i + 1) : -1;
    if (close > 0 && !this.inWord && lead.every((w) => LEADING_WORDS.has(w))) {
      const inner = this.text.slice(this.i + 2, close - 1);
      const parts = this.argv.at(-1) === "for" ? arithmeticParts(inner) : void 0;
      const bodies = textBodies(parts === void 0 ? inner : parts.slice(0, 2).join(";"));
      if (bodies === void 0 || parts !== void 0 && textBodies(parts[2]) === void 0) {
        this.failed = true;
        return;
      }
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : void 0);
      this.argv.push(this.text.slice(this.i, close + 1));
      this.i = close;
      return;
    }
    const rest = this.text.slice(this.i + 1).trimStart();
    const name = this.inWord ? this.word : this.argv.at(-1) ?? "";
    const head = this.inWord ? this.argv : this.argv.slice(0, -1);
    const leading = head.at(-1) === "function" ? head.slice(0, -1) : head;
    if (rest.startsWith(")") && leading.every((w) => LEADING_WORDS.has(w)) && /^[\w.:-]+$/.test(name)) {
      this.argv = leading;
      this.word = "";
      this.inWord = false;
      this.flush();
      this.marker("func", this.before, [name]);
      this.i = this.text.indexOf(")", this.i);
      return;
    }
    this.endWord();
    this.flush();
    this.marker("(", this.before);
    this.before = "";
  }
  close() {
    if (this.cases.at(-1) === "pattern") {
      this.cases[this.cases.length - 1] = "body";
      this.word = "";
      this.inWord = false;
      this.marker("arm");
      return;
    }
    this.endCommand("");
    this.marker(")");
    this.before = ";";
  }
  /** A redirection's operator, an fd number written against it, and its target are not arguments; it is kept as the fd
   *  it sets and what that fd then holds. */
  redirect() {
    const { text } = this;
    const fd = this.inWord && /^\d+$/.test(this.word) && text[this.i] !== "&" ? Number(this.word) : void 0;
    if (fd === void 0) this.endWord();
    this.word = "";
    this.inWord = false;
    const op = /^(?:&>>?|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>)/.exec(text.slice(this.i))[0];
    let [target, end2] = readWord(text, this.i + op.length);
    const fed = {};
    if (op === "<<" || op === "<<-") {
      const quoted = /['"\\]/.test(text.slice(this.i + op.length, end2));
      this.heredocs.push([target, op === "<<-", quoted ? void 0 : this.substitutionsAt(), fed]);
    } else {
      const start = this.i + op.length;
      const [wordStop, bodies] = wordEnd(text, start);
      if (wordStop < 0) {
        this.failed = true;
        return;
      }
      end2 = wordStop;
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : void 0);
      const fedWords = op === "<<<" ? words(text.slice(start, end2)) : [];
      if (fedWords.length > 0) fed.text = fedWords.join(" ");
    }
    const to = fd ?? (op.startsWith("<") ? 0 : 1);
    if ((op === "<&" || op === ">&") && (/^\d+$/.test(target) || target === "-")) {
      this.io.push([to, target === "-" ? "null" : Number(target)]);
    } else if (op.startsWith("<<")) {
      this.io.push([to, "file", fed]);
    } else {
      this.io.push([to, target === "/dev/null" ? "null" : "file"]);
      if (op.startsWith("&") || op === ">&" && fd === void 0) this.io.push([2, 1]);
    }
    this.i = end2 - 1;
  }
  separator(ch) {
    const { text, i } = this;
    const pair = text.slice(i, i + 2);
    const state = this.cases.at(-1);
    if (state === "pattern" && ch === "|") return;
    if (state === "body" && (pair === ";;" || pair === ";&")) {
      this.endCommand(";");
      this.cases[this.cases.length - 1] = "pattern";
      this.i += text.startsWith(";;&", i) ? 2 : 1;
      return;
    }
    if (pair === "|&") this.io.push([2, 1]);
    if (pair === "&&" || pair === "||" || pair === "|&") {
      this.endCommand(pair === "|&" ? "|" : pair);
      this.i++;
    } else {
      this.endCommand(ch === "&" || ch === "|" ? ch : ";");
    }
    if (ch === "\n") this.skipHeredocs();
  }
  /** A heredoc's body starts on the next line and is input, not commands, but for the substitutions in one whose
   *  delimiter is unquoted, which run with its command. */
  skipHeredocs() {
    const { text } = this;
    let shift = 0;
    while (this.heredocs.length > 0) {
      const [delimiter, stripTabs, at, fed] = this.heredocs.shift();
      const lines = [];
      while (this.i + 1 < text.length) {
        const end2 = text.indexOf("\n", this.i + 1);
        const raw = end2 < 0 ? text.slice(this.i + 1) : text.slice(this.i + 1, end2);
        const line = stripTabs ? raw.replace(/^\t+/, "") : raw;
        this.i = end2 < 0 ? text.length - 1 : end2;
        if (line === delimiter) break;
        lines.push(line);
      }
      const body = lines.join("\n");
      fed.text = at === void 0 ? body : expanded(body);
      const bodies = at === void 0 ? [] : textBodies(body);
      if (bodies === void 0) {
        this.failed = true;
        return;
      }
      shift += this.substitute(bodies, at === void 0 ? void 0 : [at[0] + shift, at[1]]);
    }
  }
  /** Where substitutions that run with the current command go: after the reserved words that lead it, so they run
   *  only when it does; [index in items, operator before]. */
  substitutionsAt() {
    this.flushLeading();
    return [this.items.length, this.before];
  }
  /** Insert each body as a substitution at `at` [index in items, operator before]; how many items that added. */
  substitute(bodies, at) {
    const added = [];
    for (const body of bodies) {
      const items = new _Lexer(body, this.depth + 1).read();
      if (items === void 0) {
        this.failed = true;
        return 0;
      }
      added.push({ kind: "$(", argv: [], before: at?.[1] ?? "", after: "", io: [] }, ...items, { kind: ")", argv: [], before: "", after: "", io: [] });
    }
    if (at !== void 0 && added.length > 0) this.items.splice(at[0], 0, ...added);
    return added.length;
  }
  endWord() {
    if (!this.inWord) return;
    const marked = this.word;
    const word = unmark(marked);
    const state = this.cases.at(-1);
    this.word = "";
    this.inWord = false;
    this.param = 0;
    this.dollar = -1;
    const atStart = this.argv.every((w) => LEADING_WORDS.has(w));
    if (state === "head") {
      if (word === "in") this.cases[this.cases.length - 1] = "pattern";
    } else if (state === "pattern") {
      if (word === "esac") this.esac();
    } else if (word === "case" && atStart) {
      this.flush();
      this.marker("case", this.before);
      this.cases.push("head");
    } else if (word === "esac" && atStart && state === "body") {
      this.esac();
    } else if (word === "do" && this.loopHeader()) {
      this.endCommand(";");
      this.argv.push(word);
    } else if (isAssignment(word) && this.argv.every((w) => isAssignment(w) || LEADING_WORDS.has(w))) {
      this.argv.push(word);
    } else {
      const expanded2 = braces(marked).map(unmark);
      this.argv.push(...expanded2.length === 1 ? expanded2 : expanded2.filter((w) => w !== ""));
    }
  }
  /** Whether the words so far end in a for or select header with no `in` list, which a `do` may follow at once. */
  loopHeader() {
    let n = 0;
    while (n < this.argv.length && LEADING_WORDS.has(this.argv[n])) n++;
    const core = this.argv.slice(n);
    return core.length === 2 && (core[0] === "for" || core[0] === "select") && core[1] !== "in";
  }
  esac() {
    this.flush();
    this.cases.pop();
    this.marker("esac");
  }
  /** Emit the reserved words that lead the current command, so a substitution in it runs only when they let it. */
  flushLeading() {
    let n = 0;
    while (n < this.argv.length && (LEADING_WORDS.has(this.argv[n]) || this.argv[n] === "function")) {
      n += this.argv[n] === "function" ? 2 : 1;
    }
    if (n === 0) return;
    this.items.push({ kind: "cmd", argv: this.argv.slice(0, n), before: this.before, after: "", io: [] });
    this.argv = this.argv.slice(n);
    this.before = "";
  }
  /** Emit the reserved words read so far ahead of the compound command they lead. */
  flush() {
    if (this.argv.length === 0) return;
    this.items.push({ kind: "cmd", argv: this.argv, before: this.before, after: "", io: this.io });
    this.argv = [];
    this.io = [];
    this.before = "";
  }
  endCommand(after) {
    this.endWord();
    if (this.argv.length > 0) {
      const item = { kind: "cmd", argv: this.argv, before: this.before, after, io: this.io };
      this.items.push(item);
      this.ends.set(item, this.i);
      this.before = after;
    } else {
      const last = this.items.at(-1);
      if (last !== void 0 && (last.kind === ")" || last.kind === "esac") && (after !== "" || this.io.length > 0)) {
        last.after = after;
        last.io = this.io;
      }
      if (after !== ";" && after !== "") this.before = after;
    }
    this.argv = [];
    this.io = [];
  }
};
function braces(word) {
  for (let start = word.indexOf(""); start >= 0; start = word.indexOf("", start + 1)) {
    let depth = 0;
    let end2 = -1;
    const commas = [];
    for (let j = start; j < word.length && end2 < 0; j++) {
      if (word[j] === "") depth++;
      else if (word[j] === "") depth--;
      if (word[j] === "" && depth === 1) commas.push(j);
      if (depth === 0) end2 = j;
    }
    if (end2 < 0) continue;
    const bounds = [start, ...commas, end2];
    const parts = commas.length > 0 ? bounds.slice(1).map((bound, k) => word.slice(bounds[k] + 1, bound)) : sequence(word.slice(start + 1, end2));
    if (parts === void 0) continue;
    const tails = braces(word.slice(end2 + 1));
    const out = [];
    for (const whole of parts) {
      for (const part of braces(whole)) {
        for (const tail of tails) {
          if (out.length >= MAX_WORDS) return out;
          out.push(word.slice(0, start) + part + tail);
        }
      }
    }
    return out;
  }
  return [word];
}
function sequence(body) {
  const match = /^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$/.exec(body);
  if (match === null) return void 0;
  const [, first = "", last = "", by] = match;
  const letters = /^[A-Za-z]$/.test(first);
  if (letters !== /^[A-Za-z]$/.test(last)) return void 0;
  const step = Math.abs(Number(by ?? 1)) || 1;
  const a = letters ? first.charCodeAt(0) : Number(first);
  const b = letters ? last.charCodeAt(0) : Number(last);
  const width = !letters && (/^-?0\d/.test(first) || /^-?0\d/.test(last)) ? Math.max(first.length, last.length) : 0;
  const out = [];
  for (let n = a; (b >= a ? n <= b : n >= b) && out.length < MAX_WORDS; n += b >= a ? step : -step) {
    const digits = String(Math.abs(n)).padStart(width - (n < 0 ? 1 : 0), "0");
    out.push(letters ? String.fromCharCode(n) : n < 0 ? `-${digits}` : digits);
  }
  return out;
}
function words(text) {
  return (new Lexer(text).read() ?? []).filter((item) => item.kind === "cmd").flatMap((item) => item.argv);
}
function envValue(env, processEnv, key) {
  if (key in env) return env[key];
  return CLEAN_ENV in env ? "" : processEnv[key] ?? "";
}
function isAssignment(token) {
  const eq = token.indexOf("=");
  return eq > 0 && /^[A-Za-z_][A-Za-z0-9_]*\+?$/.test(token.slice(0, eq));
}
function appends(argv, shell) {
  const given = /* @__PURE__ */ new Map();
  const out = [...argv];
  const bare = argv.every(isAssignment);
  for (let i = 0; i < out.length && isAssignment(out[i]); i++) {
    const word = out[i];
    let name = word.slice(0, word.indexOf("="));
    let value = word.slice(word.indexOf("=") + 1);
    if (name.endsWith("+")) {
      name = name.slice(0, -1);
      value = (bare ? given.get(name) ?? variable(shell, name)[0] ?? "" : SUBSTITUTED) + value;
      out[i] = `${name}=${value}`;
    }
    given.set(name, value);
  }
  return out;
}
function programName(token) {
  const name = (token.split(/[\\/]/).pop() ?? "").toLowerCase();
  return name.endsWith(".exe") ? name.slice(0, -4) : name;
}
function cdWords(args) {
  const folders = [...args];
  let letters = "";
  while (folders[0]?.startsWith("-") && folders[0] !== "-") {
    const option = folders.shift();
    if (option === "--") break;
    letters += option.slice(1);
  }
  return [letters, folders];
}
function cdTarget(args, cwd, names) {
  const [letters, folders] = cdWords(args);
  if (/[^LPeqs@0-9]/.test(letters)) return [cwd, 1];
  if (folders.length > 1 || /[^LP]/.test(letters)) return [void 0, void 0];
  const last = letters === "" ? "L" : letters[Math.max(letters.lastIndexOf("L"), letters.lastIndexOf("P"))];
  const path = expandHome(folders[0] ?? "~");
  const landed = new Set([last === "P", letters.includes("P")].map((physical) => moveTo(cwd, path, physical)));
  const target = isAbsolute3(path) ? path : cwd === void 0 || path === "-" ? void 0 : join5(cwd, path);
  if (target !== void 0 && isFile(target)) return [cwd, 1];
  if (target === void 0 || names.has(basename(normalize(target))) || landed.size > 1) return [void 0, void 0];
  const folder = [...landed][0];
  return folder === void 0 ? [cwd, 1] : [folder, 0];
}
function isFile(path) {
  try {
    return !statSync(path).isDirectory();
  } catch {
    return false;
  }
}
var LOOKS = /* @__PURE__ */ new Set([
  "cd",
  "[",
  "[[",
  "test",
  "ls",
  "echo",
  "printf",
  "stat",
  "cat",
  "wc",
  "head",
  "tail",
  "grep",
  "diff",
  "file",
  "du",
  "readlink",
  "realpath",
  "basename",
  "dirname"
]);
var MAKES_PARENTS = /* @__PURE__ */ new Set(["mkdir", "install", "git", "unzip"]);
function namedSegments(list) {
  const names = /* @__PURE__ */ new Set();
  for (const item of list) {
    const argv = item.kind === "cmd" ? item.argv.filter((w) => !KEYWORDS.has(w)) : [];
    const name = argv.length > 0 ? programName(argv[0]) : void 0;
    if (name === void 0 || LOOKS.has(name)) continue;
    for (const word of argv) {
      const segments = word.split("/").filter((segment) => segment !== "");
      for (const segment of MAKES_PARENTS.has(name) ? segments : segments.slice(-1)) names.add(segment);
    }
  }
  return names;
}
function moveTo(cwd, path, physical) {
  const target = expandHome(path);
  const folder = isAbsolute3(target) ? target : cwd === void 0 || target === "-" ? void 0 : cwd.endsWith(sep) ? cwd + target : cwd + sep + target;
  try {
    if (folder === void 0 || !statSync(folder).isDirectory()) return void 0;
    const landed = physical ? realpathSync.native(folder) : normalize(folder);
    return statSync(landed).isDirectory() ? landed : void 0;
  } catch {
    return void 0;
  }
}
function program(input, start) {
  const argv = [...input];
  const out = { args: [], env: {}, cwd: start, otherUser: false };
  let wrapper;
  let operands = 0;
  let optionsDone = false;
  for (let i = 0; i < argv.length; ) {
    const token = argv[i++];
    if (isAssignment(token) && (wrapper === void 0 || optionsDone || wrapper === "env" || wrapper === "sudo")) {
      out.env[token.slice(0, token.indexOf("="))] = token.slice(token.indexOf("=") + 1);
    } else if (wrapper !== void 0 && !optionsDone && token === "--") {
      optionsDone = true;
    } else if (wrapper === "env" && !optionsDone && (token === "-" || token === "--ignore-environment")) {
      out.env = { [CLEAN_ENV]: "" };
    } else if (wrapper !== void 0 && !optionsDone && token.startsWith("-") && token !== "-") {
      if (wrapper === "command" && (token === "-v" || token === "-V")) return { ...out, args: [] };
      i = wrapperOption(wrapper, token, argv, i, out);
    } else if (wrapper !== void 0 && operands > 0) {
      operands--;
    } else if (programName(token) in WRAPPERS) {
      wrapper = programName(token);
      optionsDone = false;
      operands = WRAPPERS[wrapper].operands;
      out.otherUser ||= wrapper === "sudo" || wrapper === "doas";
    } else {
      return { ...out, name: programName(token), args: argv.slice(i) };
    }
  }
  return out;
}
function wrapperOption(wrapper, token, argv, start, out) {
  const spec = WRAPPERS[wrapper];
  let i = start;
  let name = token;
  let value;
  if (token.startsWith("--")) {
    const eq = token.indexOf("=");
    if (eq >= 0) {
      name = token.slice(0, eq);
      value = token.slice(eq + 1);
    } else if (spec.long.includes(token) && i < argv.length) {
      value = argv[i++];
    }
  } else {
    for (let j = 1; j < token.length; j++) {
      const flag = token[j];
      if (wrapper === "env" && flag === "i") out.env = { [CLEAN_ENV]: "" };
      if (!spec.short.includes(flag)) continue;
      name = `-${flag}`;
      value = token.slice(j + 1);
      if (value === "" && i < argv.length) value = argv[i++];
      break;
    }
  }
  if (value === void 0) return i;
  if ((WRAPPER_CHDIR[wrapper] ?? []).includes(name)) out.cwd = moveTo(out.cwd, value, true);
  else if (wrapper === "env" && (name === "-S" || name === "--split-string")) argv.splice(i, 0, ...words(value));
  else if (wrapper === "env" && (name === "-u" || name === "--unset")) out.env[value] = "";
  return i;
}
function both(a, b) {
  if (a === false || b === false) return false;
  return a === void 0 || b === void 0 ? void 0 : true;
}
function follows(before, status) {
  return !(before === "&&" && status === 1 || before === "||" && status === 0);
}
function runs(shell) {
  const top = shell.frames.at(-1);
  return top === void 0 ? shell.live : top.runs;
}
function snapshot(shell) {
  return [shell.cwd, { ...shell.vars }, new Map(shell.functions)];
}
function restore(shell, saved, subshell = false) {
  if (saved === void 0) return;
  shell.cwd = saved[0];
  shell.vars = { ...saved[1] };
  if (subshell) shell.functions = new Map(saved[2]);
}
function changes(shell, saved) {
  const names = /* @__PURE__ */ new Set();
  for (const key of /* @__PURE__ */ new Set([...Object.keys(saved[1]), ...Object.keys(shell.vars)])) {
    const [before, now] = [saved[1][key], shell.vars[key]];
    if (before?.[0] !== now?.[0] || before?.[1] !== now?.[1]) names.add(key);
  }
  if (shell.cwd !== saved[0]) names.add("");
  return names;
}
function forget(shell, names) {
  for (const name of names) {
    if (name === "") shell.cwd = void 0;
    else shell.vars[name] = [SUBSTITUTED, void 0];
  }
}
function variable(shell, name) {
  const set = shell.vars[name];
  if (set !== void 0) return set;
  const inherited = !(CLEAN_ENV in shell.vars) && shell.processEnv[name] !== void 0;
  return [inherited ? shell.processEnv[name] : void 0, inherited];
}
function exportedEnv(shell) {
  const env = {};
  for (const [name, [value, exported]] of Object.entries(shell.vars)) {
    env[name] = exported === void 0 ? SUBSTITUTED : exported && value !== void 0 ? value : "";
  }
  return env;
}
function doubt(pipe) {
  return pipe.prior === void 0 && (pipe.before === "&&" || pipe.before === "||");
}
function pop(frames, kinds) {
  while (frames.length > 0) {
    const frame = frames.pop();
    if (kinds.includes(frame.kind)) return frame;
  }
  return void 0;
}
function pipeline(before, runsHere, shell) {
  shell.pipe = { before, prior: shell.status, runs: runsHere, negate: false, leading: false };
}
function begin(before, shell) {
  if (before === "|") shell.status = shell.pipe.prior === 0 ? 0 : void 0;
  if (before === "|" || shell.pipe.leading) return;
  if (before !== "&&" && before !== "||") shell.start = snapshot(shell);
  pipeline(before, both(runs(shell), follows(before, shell.status)), shell);
}
function end(shell) {
  const { pipe } = shell;
  let status = shell.status;
  if (pipe.runs === false) {
    status = pipe.prior;
  } else {
    if (pipe.negate) status = status === 0 ? 1 : status === 1 ? 0 : void 0;
    const skipped = pipe.before === "&&" ? 1 : pipe.before === "||" ? 0 : void 0;
    if (pipe.prior === void 0 && skipped !== void 0 && status !== skipped) status = void 0;
  }
  shell.status = status;
}
function finish(after, shell) {
  if (after !== "|") end(shell);
  if (after === "&") {
    restore(shell, shell.start, true);
    shell.status = 0;
  }
}
function openFrame(kind, runsHere, shell, head) {
  const name = kind === "$(" ? void 0 : shell.function;
  let value = runsHere;
  if (name !== void 0) {
    value = false;
    shell.function = void 0;
  }
  if (kind !== "$(") shell.pipe.leading = false;
  shell.frames.push({
    kind,
    base: value,
    runs: value,
    rel: true,
    alive: true,
    decided: false,
    state: snapshot(shell),
    status: shell.status,
    calls: shell.calls.length,
    pipedIn: shell.openingPipe,
    pipedOut: endsPiped(head, shell),
    outer: [shell.pipe, shell.start],
    defines: name,
    head: [shell.at, head],
    iterates: void 0,
    repeats: false,
    forever: false,
    continued: false,
    doubt: doubt(shell.pipe),
    unsure: /* @__PURE__ */ new Set(),
    outside: liveness(shell)
  });
  shell.openingPipe = false;
  shell.start = snapshot(shell);
  pipeline("", value, shell);
}
function frameStatus(frame, status) {
  const { kind, rel } = frame;
  if (frame.left !== void 0) return frame.left[0];
  if (frame.defines !== void 0) return 0;
  if (frame.base === false || kind === "$(") return frame.status;
  if (kind === "if" && rel !== true && frame.decided !== true) return rel === false && frame.decided === false ? 0 : void 0;
  if (LOOPS.includes(kind)) {
    if (rel === false) return 0;
    return kind === "for" && rel === true ? status : void 0;
  }
  if (kind === "case") return rel === false ? 0 : void 0;
  return status;
}
function settle(frame, tail, shell) {
  shell.status = frameStatus(frame, shell.status);
  [shell.pipe, shell.start] = frame.outer;
  if (frame.defines !== void 0 && shell.pipe.runs !== false) {
    const [at, head] = frame.head;
    const maybe = shell.pipe.runs === void 0 || doubt(shell.pipe);
    shell.functions.set(frame.defines, [[head, ...shell.items.slice(at + 1, shell.at), tail], maybe]);
  }
}
function leave(frame, shell) {
  if (frame.saved === void 0) return;
  for (const name of changes(shell, frame.saved)) frame.unsure.add(name);
  restore(shell, frame.saved);
  frame.saved = void 0;
}
function doubtful(frame, shell) {
  for (const since of [frame.jumped, frame.doubt || frame.repeats ? frame.state : void 0]) {
    if (since !== void 0) for (const name of changes(shell, since)) frame.unsure.add(name);
  }
  leave(frame, shell);
  forget(shell, frame.unsure);
}
function wrap(shell, first, layer) {
  for (let i = first; i < shell.calls.length; i++) {
    const call = shell.calls[i];
    shell.calls[i] = { ...call, layers: [...call.layers, layer] };
  }
}
function liveness(shell) {
  return [shell.frames.map(({ runs: r, alive, left, jumped, repeats }) => ({ runs: r, alive, left, jumped, repeats })), shell.live];
}
function revive(outside, shell) {
  outside[0].forEach((marks, i) => Object.assign(shell.frames[i], marks));
  shell.live = outside[1];
}
function closeFrame(frame, layer, shell, background = false) {
  wrap(shell, frame.calls, layer);
  if (layer[0] && !(layer[1] || background || frame.kind === "(" || frame.kind === "$(")) {
    unsure(shell, frame.state);
    revive(frame.outside, shell);
  } else if (layer[0] || layer[1] || background) {
    restore(shell, frame.state, true);
    revive(frame.outside, shell);
  }
}
function unsure(shell, saved) {
  forget(shell, changes(shell, saved));
  for (const [name, known] of saved[2]) if (!shell.functions.has(name)) shell.functions.set(name, [known[0], true]);
  for (const [name, known] of [...shell.functions]) {
    if (saved[2].get(name) !== known) shell.functions.set(name, [known[0], true]);
  }
}
function branch(keyword2, frame, shell) {
  let holds = shell.status === 0 ? true : shell.status === 1 ? false : void 0;
  let taken;
  if (keyword2 === "then" && frame.kind === "if") {
    taken = both(frame.rel, holds);
    if (taken === true) frame.decided = true;
    else if (taken === void 0 && frame.decided === false) frame.decided = void 0;
  } else if ((keyword2 === "elif" || keyword2 === "else") && frame.kind === "if") {
    leave(frame, shell);
    taken = frame.decided === void 0 ? void 0 : !frame.decided;
  } else if (keyword2 === "do" && LOOPS.includes(frame.kind)) {
    if (frame.kind === "for" || frame.kind === "select") holds = frame.iterates;
    else if (frame.kind === "until" && holds !== void 0) holds = !holds;
    if (frame.kind === "while" || frame.kind === "until") frame.forever = holds === true;
    taken = both(frame.rel, holds);
  } else {
    return;
  }
  take(frame, taken, shell);
}
function take(frame, taken, shell) {
  frame.rel = taken;
  frame.runs = both(both(frame.base, taken), frame.alive);
  if (taken === void 0 && frame.saved === void 0) frame.saved = snapshot(shell);
  shell.start = snapshot(shell);
}
function jump(name, args, shell) {
  const { frames, floor } = shell;
  let bound = -1;
  frames.forEach((f, i) => {
    if (f.kind === "(" || f.kind === "$(" || f.pipedIn || f.pipedOut) bound = i;
  });
  let target;
  if (name === "break" || name === "continue") {
    const loops = frames.flatMap((f, i) => LOOPS.includes(f.kind) && i >= Math.max(bound, floor ?? 0) ? [i] : []);
    if (loops.length === 0) return;
    const count = /^\d+$/.test(args[0] ?? "") && Number(args[0]) > 0 ? Number(args[0]) : 1;
    target = loops[loops.length - Math.min(count, loops.length)];
  } else if (name === "return") {
    if (floor === void 0) return;
    target = Math.max(floor, bound);
  } else {
    target = Math.max(bound, 0);
  }
  const sure = !doubt(shell.pipe) && frames.slice(target + 1).every((f) => f.rel === true && f.alive === true && !f.doubt) && !frames.slice(target, target + 1).some((f) => (f.kind === "if" || f.kind === "case") && f.rel !== true);
  const outermost = frames[0];
  const whole = outermost === void 0 ? sure && shell.pipe.runs === true : sure && outermost.base === true && outermost.rel === true && !outermost.doubt;
  frames.slice(target).forEach((frame2, i) => {
    frame2.alive = both(frame2.alive, sure ? false : void 0);
    frame2.runs = both(frame2.runs, frame2.alive);
    frame2.repeats &&= !(sure && (name !== "continue" || i > 0));
  });
  if (name === "exit" && bound < 0) shell.live = both(shell.live, whole ? false : void 0);
  const frame = frames[target];
  if (frame === void 0) return;
  const status = name === "break" || name === "continue" ? Number(shell.pipe.negate) : shell.status;
  frame.left = [sure && frame.left === void 0 ? status : void 0];
  if (!sure && frame.jumped === void 0) frame.jumped = snapshot(shell);
  if (name === "continue") frame.continued = frame.continued === true || sure ? true : void 0;
}
function keyword(argv, item, shell) {
  const [word = "", ...rest] = argv;
  const { frames } = shell;
  if (word === "{" || word === "if" || LOOPS.includes(word)) {
    openFrame(word, shell.pipe.runs, shell, { kind: "cmd", argv, before: "", after: item.after, io: item.io });
    if (LOOPS.includes(word)) {
      const frame = frames.at(-1);
      [frame.iterates, frame.repeats, frame.forever, frame.counter] = loop(word, rest, shell);
      touched(frame, loopCommands(frame, shell, shell.ends.get(`${shell.at},${item.argv.length - argv.length}`)?.[1]));
    }
    return word === "for" || word === "select" ? [] : rest;
  }
  if (word === "!" || word === "function") {
    if (word === "!") shell.pipe.negate = !shell.pipe.negate;
    else shell.function = rest[0] ?? "";
    shell.pipe.leading = true;
    return word === "!" ? rest : rest.slice(1);
  }
  if (word === "}" || word === "fi" || word === "done") {
    const frame = pop(frames, word === "}" ? ["{"] : word === "fi" ? ["if"] : LOOPS);
    if (frame !== void 0) {
      stepSubstitutions(frame, shell);
      const ends = endless(frame, shell);
      doubtful(frame, shell);
      settle(frame, { kind: "cmd", argv: [word], before: item.before, after: "", io: item.io }, shell);
      if (ends) jump("exit", [], shell);
    }
    shell.closed = frame;
    return rest;
  }
  const top = frames.at(-1);
  if (top !== void 0) branch(word, top, shell);
  pipeline("", runs(shell), shell);
  return rest;
}
function loop(word, rest, shell) {
  if (word === "for" && rest[0]?.startsWith("((")) return counted(rest[0]);
  if (word !== "for" && word !== "select") return [void 0, true, false, void 0];
  const listed = rest[1] === "in" ? rest.slice(2) : shell.args;
  const literal = word === "for" && (listed ?? []).some((w) => !w.includes("$") && !w.includes(SUBSTITUTED));
  const plain = listed?.length === 1 && ![..."$*?[", SUBSTITUTED].some((c) => listed[0].includes(c));
  return [literal ? true : listed?.length === 0 ? false : void 0, word !== "for" || !plain, false, void 0];
}
var TESTS = {
  "<": (a, b) => a < b,
  "<=": (a, b) => a <= b,
  ">": (a, b) => a > b,
  ">=": (a, b) => a >= b,
  "==": (a, b) => a === b,
  "!=": (a, b) => a !== b
};
function counted(word) {
  const unknown = [void 0, true, false, void 0];
  const parts = word.endsWith("))") ? (arithmeticParts(word.slice(2, -2)) ?? []).map((p) => p.trim()) : [];
  if (parts.length !== 3) return unknown;
  const [init, check, step] = parts;
  const start = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0|[1-9][0-9]*)$/.exec(init);
  if (init !== "" && start === null) return unknown;
  if (check === "") return [true, true, true, void 0];
  const test = /^([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*(0|[1-9][0-9]*)$/.exec(check);
  if (start === null || test === null || start[1] !== test[1]) return unknown;
  const [a, op, b] = [BigInt(start[2]), test[2], BigInt(test[3])];
  const holds = TESTS[op];
  if (!holds(a, b)) return [false, false, false, start[1]];
  const by = stepOf(step, start[1]);
  if (by === void 0) return [true, true, false, start[1]];
  const forever = op === "!=" ? by === 0n || (b - a) % by !== 0n || (b - a) / by < 0n : op === "==" ? by === 0n : by === 0n || by > 0n === (op === ">" || op === ">=");
  return [true, holds(a + by, b), forever, start[1]];
}
function stepOf(step, name) {
  if (step === "") return 0n;
  let match = /^(\+\+|--)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--)?$/.exec(step);
  if (match !== null && match[2] === name && match[1] === void 0 !== (match[3] === void 0)) {
    return (match[1] ?? match[3]) === "++" ? 1n : -1n;
  }
  match = /^([A-Za-z_][A-Za-z0-9_]*)\s*([+-])=\s*(0|[1-9][0-9]*)$/.exec(step);
  if (match !== null && match[1] === name) return BigInt(match[3]) * (match[2] === "+" ? 1n : -1n);
  match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*([+-])\s*(0|[1-9][0-9]*)$/.exec(step);
  if (match !== null && match[1] === name && match[2] === name) return BigInt(match[4]) * (match[3] === "+" ? 1n : -1n);
  return void 0;
}
function stepSubstitutions(frame, shell) {
  const header = frame.kind === "for" ? frame.head[1].argv[1] : void 0;
  const parts = header?.startsWith("((") ? arithmeticParts(header.slice(2, -2)) : void 0;
  const items = [];
  for (const body of parts === void 0 ? [] : textBodies(parts[2]) ?? []) {
    items.push(
      { kind: "$(", argv: [], before: "", after: "", io: [] },
      ...new Lexer(body).read() ?? [],
      { kind: ")", argv: [], before: "", after: "", io: [] }
    );
  }
  if (items.length === 0) return;
  const ended = [frame.alive, frame.continued];
  const reached = ended.includes(true) ? true : ended.every((e) => e === false) ? false : void 0;
  const runsBefore = frame.runs;
  frame.runs = both(both(frame.base, frame.rel), reached);
  shell.frames.push(frame);
  walkItems(items, shell, 0);
  shell.frames.pop();
  frame.runs = runsBefore;
}
function loopCommands(frame, shell, end2) {
  const [at, head] = frame.head;
  if (end2 === void 0) return void 0;
  return [head.argv.slice(head.argv[0] === "for" || head.argv[0] === "select" ? 2 : 1), ...ownCommands(shell.items.slice(at + 1, end2))];
}
function ownCommands(list) {
  let depth = 0;
  const commands = [];
  for (const item of list) {
    depth += item.kind === "(" || item.kind === "$(" ? 1 : item.kind === ")" ? -1 : 0;
    if (item.kind === "cmd" && depth === 0) commands.push(item.argv);
  }
  return commands;
}
function touched(frame, commands) {
  const name = frame.counter;
  if (name === void 0) return;
  for (const word of (commands ?? [[name]]).flat()) {
    for (let at = word.indexOf(name); at >= 0; at = word.indexOf(name, at + 1)) {
      const [before, after] = [word.slice(0, at), word.slice(at + name.length)];
      const whole = !/[A-Za-z0-9_]/.test(before.slice(-1) + after.slice(0, 1));
      if (whole && !(before.endsWith("$") || before.endsWith("${") && after.startsWith("}"))) {
        [frame.repeats, frame.forever] = [true, false];
        return;
      }
    }
  }
}
function leaves(commands, shell, called, seen) {
  for (const words2 of commands) {
    for (let k = 0; k < words2.length; k++) {
      const word = words2[k];
      const count = words2[k + 1] ?? "1";
      if (["break", "eval", "source", "."].includes(word) || word === "return" && !called || word === "continue" && !(/^\d+$/.test(count) && Number(count) <= 1)) return true;
      const known = shell.functions.get(word);
      if (known !== void 0 && !seen.has(word)) {
        seen.add(word);
        if (leaves(ownCommands(known[0]), shell, true, seen)) return true;
      }
    }
  }
  return false;
}
function endless(frame, shell) {
  const commands = LOOPS.includes(frame.kind) ? loopCommands(frame, shell, shell.at) : void 0;
  return commands !== void 0 && frame.forever && frame.base !== false && !leaves(commands, shell, false, /* @__PURE__ */ new Set());
}
function arithmetic(word) {
  const inner = word.startsWith("((") && word.endsWith("))") ? word.slice(2, -2).trim() : "";
  return /^(?:0+|[1-9][0-9]*)$/.test(inner) ? Number(/^0+$/.test(inner)) : void 0;
}
function marker(item, shell) {
  const { frames, pipe } = shell;
  if (item.kind === "(" || item.kind === "case") {
    begin(item.before, shell);
    shell.openingPipe = item.before === "|";
    openFrame(item.kind, shell.pipe.runs, shell, { kind: item.kind, argv: [], before: "", after: "", io: [] });
    if (item.kind === "case") {
      const frame = frames.at(-1);
      frame.rel = false;
      frame.runs = false;
    }
  } else if (item.kind === "$(") {
    const runsHere = item.before === "|" || pipe.leading ? pipe.runs : both(runs(shell), follows(item.before, shell.status));
    shell.openingPipe = item.before === "|";
    openFrame(item.kind, runsHere, shell, item);
  } else if (item.kind === "func") {
    begin(item.before, shell);
    shell.function = item.argv[0] ?? "";
    shell.pipe.leading = true;
  } else if (item.kind === "arm" && frames.at(-1)?.kind === "case") {
    const frame = frames.at(-1);
    leave(frame, shell);
    take(frame, void 0, shell);
  } else if (item.kind === ")" || item.kind === "esac") {
    const frame = pop(frames, item.kind === ")" ? ["(", "$("] : ["case"]);
    if (frame === void 0) return;
    if (item.kind === ")") restore(shell, frame.state, true);
    else doubtful(frame, shell);
    settle(frame, { ...item, after: "" }, shell);
    if (frame.kind === "$(") {
      closeFrame(frame, [frame.pipedIn, false, [[1, "null"]]], shell);
    } else {
      closeFrame(frame, [frame.pipedIn, item.after === "|", item.io], shell, item.after === "&");
      finish(item.after, shell);
    }
  }
}
function builtin(name, args, cwd, shell) {
  if (name === "cd") shell.cwd = cdTarget(args, cwd, shell.names)[0];
  else if (name === "unset") unset(args, shell);
  else if (DECLARES.includes(name)) declare(name, args, shell);
  else assign(name, args, shell);
}
function assign(name, args, shell) {
  for (const arg of args.filter((a) => !a.startsWith("-"))) {
    const eq = arg.indexOf("=");
    const key = eq < 0 ? arg : arg.slice(0, eq);
    const value = eq < 0 ? void 0 : arg.slice(eq + 1);
    if (key.endsWith("+")) forget(shell, new Set([key.slice(0, -1)].filter(Boolean)));
    else if (name === "export") shell.vars[key] = [value ?? variable(shell, key)[0], !args.includes("-n")];
    else shell.vars[key] = [value, variable(shell, key)[1]];
  }
}
function unset(args, shell) {
  const sure = shell.pipe.runs === true && !doubt(shell.pipe);
  for (const name of args.filter((a) => !a.startsWith("-"))) {
    const value = variable(shell, name)[0];
    const known = shell.functions.get(name);
    if (!args.includes("-f")) shell.vars[name] = [void 0, false];
    const unsetsFunction = args.includes("-f") || !args.includes("-v") && (value === void 0 || value.includes(SUBSTITUTED));
    if (known === void 0 || !unsetsFunction) continue;
    if (sure && args.includes("-f")) shell.functions.delete(name);
    else shell.functions.set(name, [known[0], true]);
  }
}
function declare(name, args, shell) {
  let on = "";
  let off = "";
  let i = 0;
  for (; i < args.length && /^[-+]./.test(args[i]); i++) {
    const option = args[i];
    if (option === "--") {
      i++;
      break;
    }
    if (option[0] === "-") on += option.slice(1);
    else off += option.slice(1);
  }
  const plain = (name === "declare" || name === "typeset") && shell.floor === void 0 && /^x*$/.test(on + off) && !(on !== "" && off !== "");
  for (const arg of args.slice(i)) {
    const eq = arg.indexOf("=");
    const key = eq < 0 ? arg : arg.slice(0, eq);
    if (!plain || key.endsWith("+")) {
      forget(shell, new Set([key.replace(/\+$/, "")].filter(Boolean)));
      continue;
    }
    const [current, exported] = variable(shell, key);
    shell.vars[key] = [eq < 0 ? current : arg.slice(eq + 1), on !== "" ? true : off !== "" ? false : exported];
  }
}
function stdinScript(name, args) {
  if (!SHELLS.has(name)) return void 0;
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    const option = arg.length > 1 && (arg[0] === "-" || arg[0] === "+");
    if (["-o", "+o", "-O", "+O", "--rcfile", "--init-file"].includes(arg)) i++;
    else if (arg === "-") return args.slice(i);
    else if (arg === "--") return i < args.length ? void 0 : [];
    else if (option && arg[1] !== "-" && (arg.includes("c") || arg.includes("s"))) return arg.includes("c") ? void 0 : args.slice(i);
    else if (!option) return void 0;
  }
  return [];
}
function scriptStdin(text, lexer, list) {
  return list.map((item) => {
    const end2 = lexer.ends.get(item);
    const lineEnd = end2 === void 0 ? -1 : text.indexOf("\n", end2);
    const rest = lineEnd >= 0 ? text.slice(lineEnd + 1) : "";
    return rest.trim() === "" ? item : { ...item, io: [[0, "file", { text: rest }], ...item.io] };
  });
}
function stdinText(layers) {
  let fed;
  for (const [pipedIn, , redirections] of [...layers].reverse()) {
    if (pipedIn) fed = void 0;
    for (const [fd, , text] of redirections) if (fd === 0) fed = text;
  }
  return fed?.text;
}
function stdinArgs(tool, args, text) {
  const names = tool === "curl" ? ["-K", "--config"] : ["-i", "--input-file"];
  const out = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    const joined = arg === `${names[0]}-` || arg === `${names[1]}=-`;
    if (text === void 0 || !(joined || names.includes(arg) && args[i] === "-")) {
      out.push(arg);
      continue;
    }
    if (!joined) i++;
    out.push(...tool === "curl" ? curlConfig(text) : text.split("\n").map((line) => line.trim()).filter(Boolean));
  }
  return out;
}
function curlConfig(text) {
  const args = [];
  for (const line of text.split("\n").map((l) => l.trim())) {
    const match = /^(-{0,2}[A-Za-z0-9][A-Za-z0-9-]*)(?:\s*[=:]\s*|\s+|$)(.*)$/.exec(line);
    if (match === null || line.startsWith("#")) continue;
    const [name, value] = [match[1], match[2].trim()];
    args.push(name.startsWith("-") ? name : `--${name}`);
    if (value !== "") args.push(value.length > 1 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value);
  }
  return args;
}
function shellString(name, args) {
  if (SHELLS.has(name)) {
    let hasC = false;
    for (let i = 0; i < args.length; ) {
      const arg = args[i++];
      if (["-o", "+o", "-O", "+O"].includes(arg)) i++;
      else if ((arg.startsWith("-") || arg.startsWith("+")) && !arg.startsWith("--") && arg.length > 1) hasC ||= arg.includes("c");
      else if (!arg.startsWith("--")) return hasC ? arg : void 0;
    }
  }
  if (POWERSHELLS.has(name)) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      const flag = arg.startsWith("-") || arg.startsWith("/") ? arg.slice(1).toLowerCase() : "";
      if (flag === "c" || flag.length >= 3 && "command".startsWith(flag)) return args.slice(i + 1).join(" ");
    }
  }
  return void 0;
}
function callFunction(known, layer, subshell, shell, depth) {
  const [body, maybe] = known;
  if (depth >= MAX_DEPTH || shell.callsLeft <= 0) {
    shell.status = void 0;
    return;
  }
  shell.callsLeft--;
  const first = shell.calls.length;
  const state = snapshot(shell);
  const outer = [shell.pipe, shell.start, shell.floor];
  const outside = liveness(shell);
  shell.floor = shell.frames.length;
  walkItems(body, shell, depth + 1);
  [shell.pipe, shell.start, shell.floor] = outer;
  wrap(shell, first, layer);
  if (subshell) {
    restore(shell, state, true);
    revive(outside, shell);
  } else if (subshell === void 0 || maybe || doubt(shell.pipe)) {
    unsure(shell, state);
    soften(outside, shell);
  }
}
function soften(outside, shell) {
  outside[0].forEach((marks, i) => {
    const frame = shell.frames[i];
    if (frame.alive === false && marks.alive !== false) {
      frame.alive = void 0;
      frame.runs = both(marks.runs, void 0);
      frame.jumped ??= snapshot(shell);
    }
    if (frame.left !== marks.left) frame.left = [void 0];
    frame.repeats = marks.repeats;
  });
  if (shell.live === false && outside[1] !== false) shell.live = void 0;
}
function simple(words2, item, before, shell, depth) {
  const layer = [before === "|", item.after === "|", item.io];
  const substituted = words2.some((word) => word.includes(SUBSTITUTED));
  const argv = appends(words2, shell);
  const subshell = item.after === "|" || item.after === "&" ? true : before === "|" ? void 0 : false;
  const called = argv.find((word) => !isAssignment(word));
  const known = called === void 0 ? void 0 : shell.functions.get(called);
  if (known !== void 0) {
    const outer = shell.args;
    shell.args = argv.slice(argv.indexOf(called) + 1);
    callFunction(known, layer, subshell, shell, depth);
    shell.args = outer;
    if (!known[1]) return [];
  }
  const parsed = program(argv, shell.cwd);
  const { name, args } = parsed;
  const env = CLEAN_ENV in parsed.env ? parsed.env : { ...exportedEnv(shell), ...parsed.env };
  const assigns = name === void 0 && argv.every(isAssignment);
  const status = shell.status;
  shell.status = name === "true" || name === ":" || name === "break" || name === "continue" ? 0 : name === "false" ? 1 : argv.length === 1 ? arithmetic(argv[0]) : void 0;
  if (assigns && !substituted) shell.status = 0;
  if (name === "cd") shell.status = cdTarget(args, parsed.cwd, shell.names)[1];
  if (name === "set" || name === "shift") shell.args = void 0;
  if (name === "return" || name === "exit") {
    const given = args[0];
    shell.status = given === void 0 ? status : /^\d+$/.test(given) ? Number(BigInt(given) % 256n > 0n) : void 0;
    if (name === "return" && shell.floor === void 0) shell.status = 1;
  }
  if (name === "return" || name === "exit" || name === "break" || name === "continue") jumpFrom(name, args, subshell, shell);
  if (name === "cd" || name === "export" || name === "unset" || DECLARES.includes(name) || assigns) {
    if ((before !== "|" && item.after !== "|" || subshell === void 0) && execsThrough(argv) === false) {
      const saved = snapshot(shell);
      builtin(name ?? "", assigns ? argv : args, parsed.cwd, shell);
      if (subshell === void 0) unsure(shell, saved);
      else if (doubt(shell.pipe)) forget(shell, changes(shell, saved));
    }
    replaceShell(argv, subshell, shell);
    return [];
  }
  let inner = name === void 0 ? void 0 : shellString(name, args);
  let positional = inner !== void 0 && SHELLS.has(name) ? args.slice(args.indexOf(inner) + 2) : [];
  const script = name !== void 0 && inner === void 0 ? stdinScript(name, args) : void 0;
  if (script !== void 0) {
    [inner, positional] = [stdinText([layer]), script];
    layer[2] = layer[2].map(([fd, value]) => [fd, fd === 0 ? "null" : value]);
  }
  if (inner !== void 0) {
    const lexer = new Lexer(inner, depth + 1);
    const read = lexer.read() ?? [];
    const calls = walk(script === void 0 ? read : scriptStdin(inner, lexer, read), parsed.cwd, env, shell.processEnv, depth + 1, positional);
    return replaced(argv, subshell, shell, calls.map((call) => ({
      ...call,
      otherUser: call.otherUser || parsed.otherUser,
      layers: [...call.layers, layer]
    })));
  }
  if (name === void 0) return [];
  return replaced(argv, subshell, shell, [{ name, args, env, cwd: parsed.cwd, otherUser: parsed.otherUser, layers: [layer] }]);
}
function replaced(argv, subshell, shell, calls) {
  replaceShell(argv, subshell, shell);
  return calls;
}
function replaceShell(argv, subshell, shell) {
  const replacing = execsThrough(argv);
  if (replacing !== false) jumpFrom("exit", [], replacing === true || subshell === true ? subshell : void 0, shell);
}
function execsThrough(argv) {
  let rest = argv.filter((word) => !isAssignment(word));
  let behindCommand = false;
  while (rest.length > 0 && ["command", "builtin", "time", "-p", "--"].includes(rest[0])) {
    behindCommand ||= rest[0] === "command";
    rest = rest.slice(1);
  }
  return rest.length > 1 && rest[0] === "exec" ? behindCommand ? void 0 : true : false;
}
function jumpFrom(name, args, subshell, shell) {
  if (subshell === true) return;
  const outside = liveness(shell);
  jump(name, args, shell);
  if (subshell === void 0) soften(outside, shell);
}
function command(item, shell, depth) {
  let argv = item.argv;
  let before = item.before;
  if (!["}", "fi", "done"].includes(argv[0])) begin(before, shell);
  shell.openingPipe = before === "|";
  while (argv.length > 0 && KEYWORDS.has(argv[0])) {
    if (argv[0] !== "!" && argv[0] !== "function") before = "";
    argv = keyword(argv, item, shell);
  }
  shell.openingPipe = false;
  const closed = shell.closed;
  shell.closed = void 0;
  if (closed !== void 0) closeFrame(closed, [closed.pipedIn, item.after === "|", item.io], shell, item.after === "&");
  let calls = [];
  if (argv.length > 0) {
    shell.pipe.leading = false;
    if (shell.pipe.runs !== false) calls = simple(argv, item, before, shell, depth);
  }
  if (argv.length > 0 || closed !== void 0) finish(item.after, shell);
  return calls;
}
function walkItems(list, shell, depth) {
  const outer = [shell.items, shell.at, shell.ends];
  shell.items = list;
  shell.ends = compoundEnds(list);
  for (let at = 0; at < list.length; at++) {
    shell.at = at;
    const item = list[at];
    if (item.kind === "cmd") shell.calls.push(...command(item, shell, depth));
    else marker(item, shell);
  }
  [shell.items, shell.at, shell.ends] = outer;
}
function compoundEnds(list) {
  const ends = /* @__PURE__ */ new Map();
  const opened = [];
  list.forEach(({ kind, argv, after }, at) => {
    if (kind === "(" || kind === "$(" || kind === "case") opened.push(`${at},0`);
    else if ((kind === ")" || kind === "esac") && opened.length > 0) ends.set(opened.pop(), [after, at]);
    for (let k = 0; kind === "cmd" && k < argv.length && KEYWORDS.has(argv[k]); ) {
      const word = argv[k];
      if ((word === "}" || word === "fi" || word === "done") && opened.length > 0) {
        ends.set(opened.pop(), [k === argv.length - 1 ? after : "", at]);
      } else if (word === "{" || word === "if" || LOOPS.includes(word)) {
        opened.push(`${at},${k}`);
        if (word === "for" || word === "select") break;
      }
      k += word === "function" ? 2 : 1;
    }
  });
  return ends;
}
function endsPiped(head, shell) {
  const item = shell.items[shell.at] ?? head;
  const k = head.kind === "cmd" && item.kind === "cmd" ? item.argv.length - head.argv.length : 0;
  const after = shell.ends.get(`${shell.at},${k}`)?.[0];
  return after === "|" || after === "&";
}
function walk(items, cwd, exported, processEnv, depth, positional = []) {
  const vars = Object.fromEntries(Object.entries(exported).map(([key, value]) => [key, [value, true]]));
  const shell = {
    cwd,
    vars,
    status: void 0,
    frames: [],
    function: void 0,
    start: [cwd, { ...vars }, /* @__PURE__ */ new Map()],
    processEnv,
    calls: [],
    openingPipe: false,
    pipe: { before: "", prior: void 0, runs: true, negate: false, leading: false },
    functions: /* @__PURE__ */ new Map(),
    callsLeft: MAX_CALLS,
    items,
    at: 0,
    live: true,
    floor: void 0,
    args: [...positional],
    ends: /* @__PURE__ */ new Map(),
    names: namedSegments(items)
  };
  walkItems(items, shell, depth);
  return shell.calls;
}
function shortOption(arg, args, start, valueFlags, seen) {
  let i = start;
  for (let j = 1; j < arg.length; j++) {
    const flag = arg[j];
    if (valueFlags.includes(flag)) {
      let value = arg.slice(j + 1);
      if (value === "" && i < args.length) value = args[i++];
      return [`-${flag}`, value, i];
    }
    seen.add(`-${flag}`);
  }
  return [arg, void 0, i];
}
function urlHost(url) {
  try {
    const text = url.trim();
    const full = text.includes("://") ? text : `http://${text}`;
    if (/^[^/]*:\/\/[^/?#]*\\/.test(full)) return "";
    const host = new URL(full).hostname.toLowerCase();
    return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  } catch {
    return "";
  }
}
function curl(args) {
  const out = [];
  const pins = [];
  for (let i = 0; ; ) {
    const [urls, sends, overrides, globoff, next] = curlRequest(args, i);
    pins.push(...overrides.filter(([option]) => option === "--resolve").map(([, value]) => value));
    const connects = overrides.filter(([option]) => option === "--connect-to").map(([, value]) => value);
    for (const url of urls) {
      const expanded2 = globoff ? [url] : curlGlob(url);
      if (expanded2 === void 0) return out;
      out.push(...expanded2.map((one) => [sends ? "out" : "in", urlHost(one), void 0, curlDial(one, connects, pins)]));
    }
    if (next >= args.length) return out;
    i = next;
  }
}
function curlGlob(url) {
  const pieces = globPieces(url);
  if (pieces === void 0) return void 0;
  let urls = [""];
  for (const [text, values] of pieces) {
    urls = urls.map((u) => u + text);
    const inHost = !urls.every((u) => /[/?#]/.test(u.includes("://") ? u.slice(u.indexOf("://") + 3) : u));
    urls = urls.flatMap((u) => (inHost ? values : values.slice(0, 1)).map((v) => u + v)).slice(0, MAX_WORDS);
  }
  return urls;
}
function globPieces(url) {
  const pieces = [];
  let text = "";
  for (let i = 0; i < url.length; ) {
    const ch = url[i];
    if (ch === "\\" && "{}[],".includes(url[i + 1] ?? "x")) {
      text += url[i + 1];
      i += 2;
      continue;
    }
    if (ch === "}" || ch === "]") return void 0;
    if (ch !== "{" && ch !== "[") {
      text += ch;
      i++;
      continue;
    }
    const close = ch === "{" ? "}" : "]";
    let end2 = i + 1;
    while (end2 < url.length && url[end2] !== close) {
      if (url[end2] === ch) return void 0;
      end2 += url[end2] === "\\" ? 2 : 1;
    }
    if (end2 >= url.length) return void 0;
    const body = url.slice(i + 1, end2);
    if (ch === "[" && body.includes(":") && ipOf(body) !== "") {
      text += url.slice(i, end2 + 1);
    } else {
      const values = ch === "{" ? body.split(/(?<!\\),/).map((v) => v.replace(/\\(.)/g, "$1")) : globRange(body);
      if (values === void 0) return void 0;
      pieces.push([text, values]);
      text = "";
    }
    i = end2 + 1;
  }
  return [...pieces, [text, [""]]];
}
function globRange(body) {
  const match = /^(?:(\d+)-(\d+)|([a-z])-([a-z])|([A-Z])-([A-Z]))(?::(\d+))?$/.exec(body);
  const step = match === null ? 0 : Number(match[7] ?? 1);
  if (match === null || step === 0) return void 0;
  const values = [];
  if (match[1] !== void 0) {
    const first = match[1];
    const width = first.startsWith("0") ? first.length : 0;
    for (let n = Number(first); n <= Number(match[2]) && values.length < MAX_WORDS; n += step) values.push(String(n).padStart(width, "0"));
  } else {
    const first = match[3] ?? match[5];
    const last = match[4] ?? match[6];
    for (let c = first.charCodeAt(0); c <= last.charCodeAt(0); c += step) values.push(String.fromCharCode(c));
  }
  return values.length > 0 ? values : void 0;
}
function ipOf(text) {
  const bare = text.trim().replace(/^\[+|\]+$/g, "");
  const family = isIP(bare);
  return family === 6 ? normalizeV6(bare) : family === 4 ? bare : "";
}
function curlDial(url, connects, pins) {
  const host = urlHost(url);
  let port;
  try {
    const text = url.trim();
    const parsed = new URL(text.includes("://") ? text : `http://${text}`);
    port = parsed.port || String(DEFAULT_PORTS[parsed.protocol.slice(0, -1).toLowerCase()] ?? "");
  } catch {
    return void 0;
  }
  const fields = (rule) => rule.split(/:(?![^[]*\])/);
  let target = [host, port];
  for (const rule of connects) {
    const parts = fields(rule);
    const [from = "", fromPort = "", to = "", toPort = ""] = parts;
    if (parts.length === 4 && ["", host].includes(cleanHost(from)) && ["", port].includes(fromPort)) {
      target = [cleanHost(to) || host, toPort || port];
      break;
    }
  }
  const pinned = /* @__PURE__ */ new Map();
  for (const pin of pins) {
    const parts = fields(pin.replace(/^[+-]+/, ""));
    const key = `${parts[0] === "*" ? "*" : cleanHost(parts[0] ?? "")} ${parts[1] ?? ""}`;
    pinned.delete(key);
    if (!pin.startsWith("-") && parts.length > 2) {
      pinned.set(key, parts.slice(2).join(":").split(",").map(ipOf).filter((ip) => ip !== ""));
    }
  }
  const named = pinned.get(`${target[0]} ${target[1]}`) ?? [];
  const addresses = named.length > 0 ? named : pinned.get(`* ${target[1]}`) ?? [];
  if (target[0] === host && addresses.length === 0) return void 0;
  return [addresses[0] ?? target[0], addresses];
}
function curlRequest(args, start) {
  const urls = [];
  const flags = /* @__PURE__ */ new Set();
  const overrides = [];
  let method = "";
  let i = start;
  while (i < args.length) {
    let arg = args[i++];
    let value;
    if (arg === "-:" || arg === "--next") break;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq >= 0) value = arg.slice(eq + 1);
      arg = eq >= 0 ? arg.slice(0, eq) : arg;
      if (arg.startsWith("--expand-")) arg = `--${arg.slice("--expand-".length)}`;
      if (eq < 0 && CURL_LONG_VALUES.has(arg) && i < args.length) value = args[i++];
    } else if (arg.startsWith("-") && arg.length > 1) {
      [arg, value, i] = shortOption(arg, args, i, CURL_SHORT_VALUES, flags);
    } else {
      urls.push(arg);
      continue;
    }
    flags.add(arg);
    if (arg === "--url" && value) urls.push(value);
    else if ((arg === "-X" || arg === "--request") && value) method = value.toUpperCase();
    else if ((arg === "--resolve" || arg === "--connect-to") && value) overrides.push([arg, value]);
  }
  const has = (set) => [...flags].some((f) => set.has(f));
  const sends = has(CURL_UPLOADS) || SENDING_METHODS.has(method) || has(CURL_BODIES) && !flags.has("-G") && !flags.has("--get");
  return [urls, Boolean(sends), overrides, flags.has("-g") || flags.has("--globoff"), i];
}
function wget(args) {
  const urls = [];
  const flags = /* @__PURE__ */ new Set();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq < 0 ? arg : arg.slice(0, eq);
      if (eq < 0 && WGET_LONG_VALUES.has(name)) i++;
      flags.add(name);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag;
      [flag, , i] = shortOption(arg, args, i, WGET_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      urls.push(arg);
    }
  }
  const direction = [...flags].some((f) => WGET_UPLOADS.has(f)) ? "out" : "in";
  return urls.map((url) => [direction, urlHost(url), void 0]);
}
function sshArgs(name, args) {
  const passthrough = [];
  const operands = [];
  const valueFlags = SSH_VALUE_FLAGS[name] ?? "";
  const identityFlags = name === "ssh" ? ["l", "o", "F", "J", "p"] : ["o", "F", "J", "P"];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    const readingOptions = operands.length === 0 || name === "ssh" && operands.length === 1;
    if (!readingOptions || !arg.startsWith("-") || arg === "-") {
      operands.push(arg);
      continue;
    }
    if (arg === "--") {
      operands.push(...args.slice(i));
      break;
    }
    let flag;
    let value;
    [flag, value, i] = shortOption(arg, args, i, valueFlags, /* @__PURE__ */ new Set());
    const option = ((value ?? "").trim().split(/[\s=]/)[0] ?? "").toLowerCase();
    if (value && identityFlags.includes(flag.slice(1)) && (flag !== "-o" || SSH_IDENTITY_OPTIONS.has(option))) {
      passthrough.push(flag === "-P" ? "-p" : flag, value);
    }
  }
  return [operands, passthrough];
}
function rsyncArgs(args, env, processEnv) {
  let shell = envValue(env, processEnv, "RSYNC_RSH");
  const operands = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (arg === "--rsh" && i < args.length) shell = args[i++];
    else if (arg.startsWith("--rsh=")) shell = arg.slice("--rsh=".length);
    else if (RSYNC_VALUE_OPTIONS.has(arg)) i++;
    else if (arg.startsWith("-") && !arg.startsWith("--")) {
      let flag;
      let value;
      [flag, value, i] = shortOption(arg, args, i, SSH_VALUE_FLAGS.rsync, /* @__PURE__ */ new Set());
      if (flag === "-e" && value !== void 0) shell = value;
    } else if (!arg.startsWith("-")) operands.push(arg);
  }
  if (!shell) return [operands, []];
  const shellArgv = words(shell);
  if (shellArgv[0] === void 0 || programName(shellArgv[0]) !== "ssh") return [operands, void 0];
  return [operands, sshArgs("ssh", [...shellArgv.slice(1), "-"])[1]];
}
function remote(arg) {
  const uri = /^(scp|sftp|rsync):\/\/(?:([^@/;:]+)(?:[;:][^@/]*)?@)?(\[[^\]/]+\]|[^/:[\]@]+)(?::(\d+))?(?=\/|$)/.exec(arg);
  if (uri !== null) {
    return [uri[2] === void 0 ? uri[3] : `${uri[2]}@${uri[3]}`, uri[4], uri[1] !== "rsync"];
  }
  if (arg.includes("://")) return void 0;
  const match = /^((?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)):(:)?/.exec(arg);
  if (match === null || process.platform === "win32" && /^[A-Za-z]:[\\/]/.test(arg)) return void 0;
  return [match[1], void 0, match[2] === void 0];
}
function copy(name, args, env, processEnv) {
  const [operands, options] = name === "rsync" ? rsyncArgs(args, env, processEnv) : sshArgs(name, args);
  let remotes;
  if (name === "sftp" && operands.length > 0) {
    const first = operands[0];
    const plain = /^(?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)$/.test(first);
    remotes = [[plain ? [first, void 0, true] : remote(first), plain ? "" : "in"]];
  } else if (operands.length === 1) {
    remotes = [[remote(operands[0]), name === "rsync" ? "in" : ""]];
  } else {
    remotes = operands.map((op, i) => [remote(op), i === operands.length - 1 ? "out" : "in"]);
  }
  const out = [];
  for (const [found, direction] of remotes) {
    if (found === void 0) continue;
    const [destination, port, viaSsh] = found;
    const sshOptions = viaSsh && options !== void 0 ? [...options, ...port === void 0 ? [] : ["-p", port]] : void 0;
    out.push([direction, destination, sshOptions]);
  }
  return out;
}
function sshPipe(args, sends, receives) {
  const [operands, options] = sshArgs("ssh", args);
  const destination = operands[0];
  if (destination === void 0) return [];
  return [["out", sends], ["in", receives]].filter(([, used]) => used).map(([d]) => [d, destination, options]);
}
function netcat(args, sends) {
  const positional = [];
  const flags = /* @__PURE__ */ new Set();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (arg.startsWith("--")) {
      if (!arg.includes("=") && NC_LONG_VALUES.has(arg)) i++;
      flags.add(arg);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag;
      [flag, , i] = shortOption(arg, args, i, NC_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      positional.push(arg);
    }
  }
  if (positional[0] === void 0 || ["-l", "--listen", "-U", "--unixsock"].some((f) => flags.has(f))) return [];
  return [[sends ? "out" : "", positional[0], void 0]];
}
function socat(args, sends) {
  const addresses = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (SOCAT_VALUE_OPTIONS.has(arg)) i++;
    else if (arg === "-" || !arg.startsWith("-")) addresses.push(arg);
  }
  const out = [];
  for (const address2 of addresses.slice(0, 2)) {
    const match = /^(?:(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?|(?:proxy|socks4a?|socks5):[^:,]+):(\[[^\]]+\]|[^:,]+):/i.exec(address2);
    if (match !== null) out.push([sends ? "out" : "", match[1], void 0]);
  }
  return out;
}
function httpieItem(item) {
  const match = /^(?:\\.|[^\\=:@])*(:=@|=@|:=|==|=|@|:)/.exec(item);
  return match !== null && match[1] !== "==" && match[1] !== ":";
}
function httpie(args, sends) {
  const positional = [];
  const flags = /* @__PURE__ */ new Set();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq < 0 ? arg : arg.slice(0, eq);
      if (eq < 0 && HTTPIE_LONG_VALUES.has(name)) i++;
      flags.add(name);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag;
      [flag, , i] = shortOption(arg, args, i, HTTPIE_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      positional.push(arg);
    }
  }
  if (positional.length === 0 || flags.has("--offline")) return [];
  const method = positional.length > 1 && /^[A-Za-z]+$/.test(positional[0]) ? positional[0].toUpperCase() : "";
  const url = method ? positional[1] : positional[0];
  const items = positional.slice(method ? 2 : 1);
  const readsStdin = sends && !flags.has("-I") && !flags.has("--ignore-stdin");
  const out = SENDING_METHODS.has(method) || flags.has("--raw") || readsStdin || items.some(httpieItem);
  return [[out ? "out" : "in", url.startsWith(":") ? "localhost" : urlHost(url), void 0]];
}
function webCmdlet(args, sends) {
  let uri = "";
  let out = sends;
  const positional = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++];
    if (!/^-[A-Za-z]/.test(arg)) {
      positional.push(arg);
      continue;
    }
    const colon = arg.indexOf(":");
    const name = (colon < 0 ? arg.slice(1) : arg.slice(1, colon)).toLowerCase();
    let value = colon < 0 ? "" : arg.slice(colon + 1);
    if (colon < 0 && !PS_SWITCHES.has(name) && i < args.length) value = args[i++];
    if (name === "uri") uri = value;
    else if (name === "body" || name === "infile" || name === "form") out = true;
    else if ((name === "method" || name === "custommethod") && SENDING_METHODS.has(value.toUpperCase())) out = true;
  }
  uri ||= positional[0] ?? "";
  return uri ? [[out ? "out" : "in", urlHost(uri), void 0]] : [];
}
function stdio(layers) {
  const fds = /* @__PURE__ */ new Map([[0, "null"], [1, "null"], [2, "null"]]);
  for (const [pipedIn, pipedOut, redirections] of [...layers].reverse()) {
    if (pipedIn) fds.set(0, "pipe");
    if (pipedOut) fds.set(1, "pipe");
    for (const [fd, value] of redirections) fds.set(fd, typeof value === "number" ? fds.get(value) ?? "null" : value);
  }
  const fed = (fd) => fds.get(fd) === "file" || fds.get(fd) === "pipe";
  return [fed(0), fed(1)];
}
function parse(call, processEnv) {
  const tool = TOOLS[call.name];
  const [sends, keeps] = stdio(call.layers);
  let raw;
  if (tool === "scp" || tool === "sftp" || tool === "rsync") raw = copy(tool, call.args, call.env, processEnv);
  else if (tool === "ssh") raw = sshPipe(call.args, sends, keeps);
  else if (tool === "curl") raw = curl(stdinArgs(tool, call.args, stdinText(call.layers)));
  else if (tool === "wget") raw = wget(stdinArgs(tool, call.args, stdinText(call.layers)));
  else if (tool === "nc") raw = netcat(call.args, sends);
  else if (tool === "socat") raw = socat(call.args, sends);
  else if (tool === "httpie") raw = httpie(call.args, sends);
  else if (tool === "powershell") raw = webCmdlet(call.args, sends);
  else return void 0;
  return [tool, raw.map(([d, dest, options, dial]) => [d, dest, call.otherUser ? void 0 : options, dial])];
}
function cleanHost(value) {
  let host = value.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (/^[a-z0-9_][a-z0-9_.-]{0,252}$/.test(host)) return host;
  const bare = host.split("%")[0];
  return host.includes(":") && isIP(bare) === 6 ? normalizeV6(bare) : "";
}
function normalizeV6(address2) {
  try {
    return new URL(`http://[${address2}]/`).hostname.slice(1, -1);
  } catch {
    return address2;
  }
}
function expandHome(path, home = homedir()) {
  return path === "~" || path.startsWith("~/") ? join5(home, path.slice(1)) : path;
}
function accountHome() {
  try {
    return userInfo().homedir || homedir();
  } catch {
    return homedir();
  }
}
function globMatch(pattern, name) {
  let p = 0;
  let n = 0;
  let star = -1;
  let mark = 0;
  while (n < name.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === name[n])) {
      p++;
      n++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = n;
    } else if (star >= 0) {
      p = star + 1;
      n = ++mark;
    } else {
      return false;
    }
  }
  while (pattern[p] === "*") p++;
  return p === pattern.length;
}
function includeTargets(pattern, bases, homes) {
  if (pattern.startsWith("~") && pattern !== "~" && !pattern.startsWith("~/") || /[$%]/.test(pattern)) return void 0;
  const unescaped = pattern.replace(/\\(.)/g, "$1");
  const fulls = unescaped === "~" || unescaped.startsWith("~/") ? homes.map((home) => expandHome(unescaped, home)) : bases.map((base) => isAbsolute3(unescaped) ? unescaped : join5(base, unescaped));
  const out = [];
  for (const full of new Set(fulls)) {
    const found = globTargets(full);
    if (found === void 0) return void 0;
    out.push(...found);
  }
  return out;
}
function globTargets(full) {
  if (!/[*?[]/.test(full)) return [full];
  if (/[*?[]/.test(dirname3(full)) || basename(full).includes("[")) return void 0;
  try {
    return readdirSync(dirname3(full)).filter((entry) => globMatch(basename(full), entry)).sort().map((entry) => join5(dirname3(full), entry));
  } catch {
    return [];
  }
}
function configWords(line) {
  const out = [];
  let word = "";
  let inWord = false;
  let quote;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (ch === "\\" && next !== void 0 && (`'"\\`.includes(next) || quote === void 0 && next === " ")) {
      word += next;
      inWord = true;
      i++;
    } else if (quote !== void 0) {
      if (ch === quote) quote = void 0;
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (ch === " " || ch === "	") {
      if (inWord) out.push(word);
      word = "";
      inWord = false;
    } else if (ch === "#" && !inWord) {
      break;
    } else {
      word += ch;
      inWord = true;
    }
  }
  if (quote !== void 0) return void 0;
  if (inWord) out.push(word);
  return out;
}
function matchExecs(words2) {
  for (let i = 0; i < words2.length; ) {
    const word = words2[i];
    const criterion = word.split("=")[0]?.toLowerCase().replace(/^!/, "") ?? "";
    if (criterion === "exec") return true;
    i += word.includes("=") || ["all", "canonical", "final"].includes(criterion) ? 1 : 2;
  }
  return false;
}
function configRuns(text, bases, homes, pending) {
  for (const line of text.split(/\r?\n/)) {
    const lineWords = configWords(line);
    if (lineWords === void 0) return true;
    const [first = "", ...rest] = lineWords;
    const [keyword2 = "", attached = ""] = first.split(/=(.*)/s);
    const args = (attached ? [attached, ...rest] : rest).map((w) => w.replace(/^=+/, "")).filter(Boolean);
    if (keyword2.toLowerCase() === "match" && matchExecs(args)) return true;
    if (keyword2.toLowerCase() === "canonicalizehostname" && ["yes", "always"].includes((args[0] ?? "").toLowerCase())) return true;
    for (const pattern of keyword2.toLowerCase() === "include" ? args : []) {
      const targets = includeTargets(pattern, bases, homes);
      if (targets === void 0) return true;
      pending.push(...targets.map((target) => [target, bases]));
    }
  }
  return false;
}
function configUnsafe(passthrough, home, processEnv) {
  const homes = [.../* @__PURE__ */ new Set([home, processEnv.HOME || home])];
  const userBases = homes.map((h) => join5(h, ".ssh"));
  let config;
  for (let i = 0; i + 1 < passthrough.length; i += 2) if (passthrough[i] === "-F") config = passthrough[i + 1];
  if (config === "none") return false;
  if (config !== void 0 && !isAbsolute3(config)) return true;
  const system = ["/etc/ssh", "/opt/homebrew/etc/ssh", "/usr/local/etc/ssh", join5(processEnv.PROGRAMDATA || "/nonexistent", "ssh")];
  const pending = config === void 0 ? [[join5(home, ".ssh", "config"), userBases], ...system.map((d) => [join5(d, "ssh_config"), [d]])] : [[config, userBases]];
  const seen = /* @__PURE__ */ new Set();
  while (pending.length > 0) {
    const [path, bases] = pending.pop();
    if (seen.has(path)) continue;
    seen.add(path);
    let text;
    try {
      const info = statSync(path, { throwIfNoEntry: false });
      if (info === void 0) continue;
      if (seen.size > SSH_CONFIG_MAX_FILES || !info.isFile() || info.size > SSH_CONFIG_MAX_BYTES) return true;
      text = readFileSync3(path, "utf8");
    } catch {
      return true;
    }
    if (configRuns(text, bases, homes, pending)) return true;
  }
  return false;
}
async function sshHostname(destination, options, cwd, state) {
  const resolved = options.map((value, i) => {
    if (options[i - 1] !== "-F") return value;
    const path = expandHome(value);
    return path === "none" || isAbsolute3(path) || cwd === void 0 ? path : join5(cwd, path);
  });
  const key = JSON.stringify([destination, resolved]);
  const cached = state.sshHosts.get(key);
  if (cached !== void 0) return cached;
  state.sshHosts.set(key, "");
  if (destination.startsWith("-") || configUnsafe(resolved, state.home, state.env)) return "";
  const out = await run(["ssh", "-G", ...resolved, "--", destination.replace(/[[\]]/g, "")], state) ?? "";
  const line = out.split(/\r?\n/).find((l) => l.startsWith("hostname "));
  const host = line === void 0 ? "" : cleanHost(line.slice("hostname ".length));
  state.sshHosts.set(key, host);
  return host;
}
var KIND_LISTS = ADDRESS_KINDS.map(([kind, networks]) => {
  const list = new BlockList();
  for (const network of networks) {
    const [address2 = "", prefix = ""] = network.split("/");
    list.addSubnet(address2, Number(prefix), address2.includes(":") ? "ipv6" : "ipv4");
  }
  return [kind, list];
});
function kindOf(raw) {
  const address2 = /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(raw) ? raw.slice(7) : raw.split("%")[0];
  const family = isIP(address2) === 6 ? "ipv6" : "ipv4";
  for (const [kind, list] of KIND_LISTS) if (list.check(address2, family)) return kind;
  return "public";
}
var hungLookups = 0;
var systemLookup = async (host) => (await dnsLookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
async function resolveAddresses(host, timeoutMs, state) {
  if (hungLookups > 0) return [];
  let timer;
  let settled = false;
  let timedOut = false;
  const pending = Promise.resolve().then(() => state.lookup(host)).then((found) => found, () => []).finally(() => {
    settled = true;
    if (timedOut) hungLookups--;
  });
  const timeout = new Promise((done) => {
    timer = setTimeout(() => {
      if (!settled) {
        timedOut = true;
        hungLookups++;
      }
      done([]);
    }, timeoutMs);
  });
  try {
    return await Promise.race([pending, timeout]);
  } finally {
    clearTimeout(timer);
  }
}
async function address(host, state) {
  const cached = state.addresses.get(host);
  if (cached !== void 0) return cached;
  let found;
  if (isIP(host) !== 0) {
    found = [host];
  } else {
    const remaining = state.deadline - state.now();
    found = remaining > 0 ? await resolveAddresses(host, Math.min(DNS_TIMEOUT_MS, remaining), state) : [];
  }
  const kind = addressKind(found);
  state.addresses.set(host, kind);
  return kind;
}
function addressKind(found) {
  const kinds = found.map(kindOf);
  return kinds.length === 0 ? "unresolved" : kinds.includes("public") ? "public" : kinds[0];
}
async function endpoint(raw, cwd, state) {
  const [direction, rawDestination, sshOptions, dial] = raw;
  const destination = rawDestination.trim();
  const host = cleanHost(destination.includes("://") ? urlHost(destination) : destination.split("@").pop() ?? "");
  if (host === "") return void 0;
  let resolved;
  let kind;
  if (dial !== void 0) {
    resolved = dial[0];
    kind = dial[1].length > 0 ? addressKind(dial[1]) : await address(dial[0], state);
  } else {
    resolved = (sshOptions === void 0 ? "" : await sshHostname(destination, sshOptions, cwd, state)) || host;
    kind = await address(resolved, state);
  }
  const out = { host, resolved_host: resolved, address: kind };
  return direction === "out" || direction === "in" ? { direction, ...out } : out;
}
async function transferOf(command2, cwd, state) {
  let tool;
  const endpoints = [];
  for (const call of walk(new Lexer(command2).read() ?? [], cwd, {}, state.env, 0)) {
    const found = parse(call, state.env);
    for (const raw of found?.[1] ?? []) {
      if (endpoints.length >= MAX_ENDPOINTS) break;
      const one = await endpoint(raw, call.cwd, state);
      if (one !== void 0 && !endpoints.some((e) => JSON.stringify(e) === JSON.stringify(one))) {
        endpoints.push(one);
        tool ??= found?.[0];
      }
    }
  }
  return tool === void 0 ? void 0 : { tool, endpoints };
}
var SHELL_TOOLS = /* @__PURE__ */ new Set(["bash", "powershell"]);
var NEVER_RAN = /* @__PURE__ */ new Set(["deny", "unavailable"]);
async function resolveTransfers(calls, cwd, opts = {}) {
  const transfers = /* @__PURE__ */ new Map();
  try {
    const now = opts.now ?? Date.now;
    const state = {
      run: opts.execFile ?? defaultExecFile,
      lookup: opts.lookup ?? systemLookup,
      env: opts.env ?? process.env,
      now,
      deadline: now() + (opts.budgetMs ?? TURN_BUDGET_MS),
      home: opts.home ?? accountHome(),
      sshHosts: /* @__PURE__ */ new Map(),
      addresses: /* @__PURE__ */ new Map()
    };
    for (const call of calls) {
      const input = call.tool_input;
      const command2 = input !== null && typeof input === "object" && !Array.isArray(input) ? input.command : void 0;
      if (typeof call.tool_name !== "string" || !SHELL_TOOLS.has(call.tool_name)) continue;
      if (typeof call.decision === "string" && NEVER_RAN.has(call.decision) || call.ran === false) continue;
      if (typeof command2 !== "string" || command2.trim() === "" || typeof call.tool_use_id !== "string") continue;
      const transfer = await transferOf(command2, cwd, state);
      if (transfer !== void 0) transfers.set(call.tool_use_id, transfer);
    }
  } catch {
  }
  return transfers;
}

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
    const dispatchedAtMs = completedAtMs;
    const post = (transfers) => deps.client.postTurnLog(
      buildTurnLogBody(record, {
        cwd,
        completedAtMs,
        assistantText,
        ...deps.apiKey === void 0 ? {} : { apiKey: deps.apiKey },
        ...deps.accountIdentity === void 0 ? {} : { accountIdentity: deps.accountIdentity },
        transfers
      })
    );
    void resolveTransfers(record.tool_calls ?? [], cwd).catch(() => /* @__PURE__ */ new Map()).then(post).then((ok) => {
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
    if (call.decision === "confirm") call.ran = false;
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
var SHELL_TOOLS2 = /* @__PURE__ */ new Set(["bash", "powershell"]);
function isShellCall(e) {
  if (!SHELL_TOOLS2.has(e.toolName)) return false;
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
    const command2 = shell ? event.input.command : "";
    const toolInput = event.input ?? {};
    const filePath = resolveFilePath(event.toolName, toolInput, ctx.cwd);
    if (command2.trim() === "" && filePath === void 0) return void 0;
    const auditInput = auditToolInput(toolInput, command2);
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
      command: command2,
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
    const result = await applyOutcome(outcome, ctx);
    if (outcome.kind === "confirm" && result !== void 0) noteSafe(() => deps.onDeclined?.(event.toolCallId));
    return result;
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
    const signals = [ui.signal, signal].filter((s) => s instanceof AbortSignal);
    const combined = signals.length === 0 ? void 0 : signals.length === 1 ? signals[0] : AbortSignal.any(signals);
    const dialogCtx = { hasUI: true, ui: ui.ui, signal: combined };
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
import { randomBytes as randomBytes2 } from "node:crypto";
var ANSWERS = /* @__PURE__ */ new Set(["allow_once", "deny", "abstain"]);
function isRecord2(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function snapshot2(data) {
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
      const request = snapshot2(data);
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
    const walk2 = (v, depth) => {
      if (depth > 64) throw new Error("too deep");
      if (v === null || typeof v !== "object") return v;
      if (seen.has(v)) throw new Error("cycle");
      seen.add(v);
      let out;
      if (Array.isArray(v)) out = v.map((item) => walk2(item, depth + 1));
      else {
        const sorted = {};
        for (const key of Object.keys(v).sort()) {
          Object.defineProperty(sorted, key, {
            value: walk2(v[key], depth + 1),
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
    const text = JSON.stringify(walk2(value, 0));
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
        expire();
        entries.push({
          toolCallId: entry.toolCallId,
          toolName: entry.toolName,
          tool,
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
    claim(prefixedToolName, originalToolName, args) {
      try {
        expire();
        const argsKey = stableKey(isRecord2(args) ? args : {});
        if (argsKey === void 0) return void 0;
        const index = entries.findIndex((entry) => {
          if (prefixedToolName !== "" && entry.toolName === prefixedToolName && entry.directKey === argsKey) {
            return true;
          }
          return mayBeWrapper(entry.toolName) && entry.wrapperKey === argsKey && entry.tool !== void 0 && (entry.tool === originalToolName || prefixedToolName !== "" && entry.tool === prefixedToolName);
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
import { closeSync, constants as fsConstants, fstatSync, lstatSync as lstatSync2, openSync, readSync, statSync as statSync2 } from "node:fs";
import { isAbsolute as isAbsolute4, join as join6 } from "node:path";
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
    if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute4(homeDir)) return void 0;
    if (typeof cwd !== "string" || cwd === "" || !isAbsolute4(cwd)) return void 0;
    if (hasMcpConfigFlag(options.argv)) return void 0;
    const packageDir = env[ENV_PI_PACKAGE_DIR];
    if (typeof packageDir === "string" && packageDir !== "") return void 0;
    const agentEnv = env[ENV_PI_AGENT_DIR];
    let agentDir;
    if (typeof agentEnv === "string" && agentEnv !== "") {
      if (!isAbsolute4(agentEnv)) return void 0;
      agentDir = agentEnv;
    } else {
      agentDir = join6(homeDir, ".pi", "agent");
    }
    const adapterFile = join6(agentDir, MCP_ADAPTER_CONFIG_FILE_NAME);
    const mode = env[ENV_PI_MCP_CONFIG_MODE];
    if (typeof mode === "string" && mode.trim().toLowerCase() === "exclusive") return [adapterFile];
    const sources = [];
    for (const path of [
      join6(homeDir, ".config", "mcp", "mcp.json"),
      join6(homeDir, ".agents", "mcp.json"),
      join6(homeDir, ".agents", "mcp", "mcp.json")
    ]) {
      if (path !== adapterFile) sources.push(path);
    }
    sources.push(adapterFile);
    const project = join6(cwd, ".mcp.json");
    if (project !== adapterFile) sources.push(project);
    sources.push(join6(cwd, ".pi", MCP_ADAPTER_CONFIG_FILE_NAME));
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
    for (const stat of [lstatSync2, statSync2]) {
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
  function take2(cwd) {
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
        if (snap === void 0) take2(cwd);
      } catch {
      }
    },
    serverConfig(serverName, cwd) {
      try {
        if (snap === void 0 && !take2(cwd)) return void 0;
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
    const command2 = typeof event.command === "string" ? event.command : "";
    if (command2.trim() === "") return void 0;
    const toolUseId = newUserBashId();
    const payload = buildPretoolPayload({
      // A user-typed command IS a bash command; Phase 7 registered the lowercase name.
      toolName: "bash",
      command: command2,
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
      tool_input: auditToolInput({}, command2)
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
  return (snapshot3) => {
    void writeCache(cachePath, {
      ...snapshot3,
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
    return homedir2();
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
    const matchedId = inflight.claim(call.prefixedToolName, call.originalToolName, call.args);
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
          },
          onDeclined: (toolUseId) => turnStore.markNotRun(toolUseId)
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
