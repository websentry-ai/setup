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
var SESSION_PRESENCE_ROW_ENABLED = true;
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
var KEY_REJECTION_THRESHOLD = 2;
var BREAKER_FAILURE_THRESHOLD = 3;
var BREAKER_OPEN_MS = 6e4;
var CACHE_TTL_MS = 3e5;
var MAX_REASON_CHARS = 2e3;
var MAX_HASH_BYTES = 4194304;
var MAX_TOOL_INPUT_BYTES = 16384;
var MAX_COMMAND_CHARS = 8192;
var MAX_PROMPT_CHARS = 8192;
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
var CONFIRM_QUESTION_SUFFIX = "\n\nRun this command?";
var NO_UI_REASON = "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
var ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable \u2014 please retry";
var NO_KEY_NOTICE = "Unbound: no API key found \u2014 extension inactive";
var BREAKER_OPEN_NOTICE = "Unbound policy engine unreachable \u2014 allowing tool calls for 60 s";
var BREAKER_CLOSED_NOTICE = "Unbound policy engine reachable again \u2014 enforcement resumed";
var KEY_REJECTED_NOTICE = "Unbound: API key rejected \u2014 enforcement inactive";

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
import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute, join } from "node:path";

// packages/core/src/policyState.ts
function parseFailureAction(raw) {
  return raw === "allow" || raw === "block" ? raw : void 0;
}
function parseToolsToCheck(raw) {
  if (!Array.isArray(raw)) return void 0;
  return raw.filter((entry) => typeof entry === "string");
}
function parseTimestamp(raw) {
  return typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? raw : void 0;
}
function createPolicyState() {
  let failureAction;
  let toolsToCheck;
  let toolsSyncedAt;
  let fetchedAt;
  return {
    recordSuccess(body, nowMs = Date.now()) {
      let learned = false;
      const nextTools = parseToolsToCheck(body?.tools_to_check);
      if (nextTools !== void 0) {
        toolsToCheck = nextTools;
        toolsSyncedAt = nowMs;
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
function buildPretoolPayload(input) {
  const metadata = {
    cwd: input.cwd,
    // Allowlist first, then the whole-object cap as defence in depth (WR-04).
    tool_input: capToolInput(sanitizeToolInput(input.toolInput))
  };
  const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd);
  if (filePath !== void 0) metadata.file_path = filePath;
  const capped = capCommand(input.command);
  if (capped.truncated) {
    metadata.command_truncated = true;
    metadata.command_original_chars = input.command.length;
  }
  const preToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears.
    tool_name: input.toolName,
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
  return body;
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
  return body;
}

// packages/core/src/cache.ts
function expandTilde(raw, homeDir) {
  if (typeof raw !== "string") return void 0;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return void 0;
  if (trimmed === "~") return homeDir;
  if (trimmed.startsWith("~/")) return join(homeDir, trimmed.slice(2));
  return trimmed;
}
function resolveCachePath(env, homeDir) {
  let base = expandTilde(env?.[ENV_PI_AGENT_DIR], typeof homeDir === "string" ? homeDir : "");
  if (base === void 0 || !isAbsolute(base)) {
    if (typeof homeDir !== "string" || homeDir.length === 0 || !isAbsolute(homeDir)) return void 0;
    base = join(homeDir, ...PI_AGENT_DIR_SEGMENTS);
  }
  if (!isAbsolute(base)) return void 0;
  return join(base, CACHE_DIR_NAME, CACHE_FILE_NAME);
}
function keyFingerprint(apiKey) {
  const material = typeof apiKey === "string" ? apiKey : "";
  return KEY_FINGERPRINT_PREFIX + createHash("sha256").update(material, "utf8").digest("hex").slice(0, 16);
}
function readCache(path, identity) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return void 0;
  }
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
  return {
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
function toolResponseFor(record, toolUseId) {
  const results = Array.isArray(record.results) ? record.results : [];
  const match = results.find((entry) => entry?.tool_use_id === toolUseId);
  if (match === void 0) return {};
  if (match.hash_skipped === true) {
    return { hash_skipped: true, content_bytes: match.content_bytes };
  }
  if (typeof match.content_sha256 === "string") {
    return { content_sha256: match.content_sha256, content_bytes: match.content_bytes };
  }
  return {};
}
function buildTurnLogBody(record, opts) {
  let conversationId = "";
  let prompt = "";
  let toolUse = [];
  let startedAt;
  try {
    const safe = record === null || typeof record !== "object" ? { tool_calls: [], results: [] } : record;
    conversationId = typeof safe.session_id === "string" ? safe.session_id : "";
    prompt = typeof safe.prompt === "string" ? safe.prompt : "";
    startedAt = typeof safe.started_at === "number" && Number.isFinite(safe.started_at) ? safe.started_at : void 0;
    const calls = Array.isArray(safe.tool_calls) ? safe.tool_calls : [];
    toolUse = calls.map((call) => ({
      type: TURNLOG_TOOL_USE_TYPE,
      tool_name: typeof call?.tool_name === "string" ? call.tool_name : "",
      tool_use_id: typeof call?.tool_use_id === "string" ? call.tool_use_id : "",
      // Not `call`-derived and not `event.input`-derived. Empty by design — header decision 2.
      tool_input: {},
      tool_response: toolResponseFor(safe, typeof call?.tool_use_id === "string" ? call.tool_use_id : "")
    }));
  } catch {
  }
  const body = {
    conversation_id: conversationId,
    model: TURNLOG_MODEL,
    messages: [
      { role: "user", content: prompt },
      { role: "assistant", content: "", tool_use: toolUse }
    ],
    cwd: opts.cwd,
    requestCompleted: new Date(opts.completedAtMs).toISOString(),
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
  if (startedAt !== void 0) body.requestInitialized = new Date(startedAt).toISOString();
  return body;
}

// packages/core/src/config.ts
import { readFileSync as readFileSync2 } from "node:fs";
import { isAbsolute as isAbsolute2, join as join2 } from "node:path";
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function readUnboundConfig(homeDir) {
  if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute2(homeDir)) return {};
  try {
    const raw = readFileSync2(join2(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), "utf8");
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

// packages/core/src/keyState.ts
var REJECTION_LABELS = /* @__PURE__ */ new Set(["HttpStatus401", "HttpStatus403"]);
function createKeyState(opts = {}) {
  const threshold = typeof opts.threshold === "number" && opts.threshold > 0 ? opts.threshold : KEY_REJECTION_THRESHOLD;
  let consecutiveRejections = 0;
  let inactive = false;
  return {
    recordFailure(errorClass) {
      if (inactive) return void 0;
      if (typeof errorClass !== "string" || !REJECTION_LABELS.has(errorClass)) {
        consecutiveRejections = 0;
        return void 0;
      }
      consecutiveRejections += 1;
      if (consecutiveRejections < threshold) return void 0;
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
import { readFileSync as readFileSync3 } from "node:fs";
import { dirname as dirname2, join as join3 } from "node:path";
var PI_PACKAGE_NAME = "@earendil-works/pi-coding-agent";
var MAX_WALK_UP_LEVELS = 8;
var MAX_VERSION_CHARS = 32;
function readManagedInstallVersion(env) {
  const root = env[ENV_PI_INSTALL_ROOT];
  if (typeof root !== "string" || root.length === 0) return void 0;
  try {
    const version = readFileSync3(join3(root, "current-version"), "utf8").trim();
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
      const parsed = JSON.parse(readFileSync3(join3(dir, "package.json"), "utf8"));
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
      const latched = keyState2.recordFailure(res.errorClass);
      if (latched !== void 0) {
        notify(hooks, KEY_REJECTED_NOTICE, "warning");
        return { kind: "allow" };
      }
      const blocked = opts.state.getFailureAction() === "block";
      opts.telemetry.reportBypass({
        errorClass: res.errorClass,
        toolName,
        elapsedMs: res.elapsedMs,
        blocked
      });
      return blocked ? { kind: "unavailable" } : { kind: "allow" };
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
  function reportBypass(ctx) {
    try {
      const apiKey = opts.apiKey;
      if (apiKey === void 0 || apiKey === "") return;
      if (opts.isInactive?.() === true) return;
      if (reporting) return;
      const at = now();
      if (lastReportAtMs !== void 0 && at - lastReportAtMs < intervalMs) return;
      lastReportAtMs = at;
      reporting = true;
      const category = ctx.blocked === true ? ERROR_CATEGORY_BLOCKED : ERROR_CATEGORY_BYPASS;
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
  return { reportBypass };
}

// packages/core/src/turn.ts
import { createHash as createHash2 } from "node:crypto";
function projectPart(part) {
  if (part === null || typeof part !== "object") return "";
  const record = part;
  if (record.type === "image") {
    const mimeType = typeof record.mimeType === "string" ? record.mimeType : "";
    const data = typeof record.data === "string" ? record.data : "";
    return `image:${mimeType}:${data}`;
  }
  const text = typeof record.text === "string" ? record.text : "";
  return `text:${text}`;
}
function hashContent(parts) {
  try {
    const list = Array.isArray(parts) ? parts : [];
    const projected = list.map(projectPart);
    let bytes = 0;
    for (let i = 0; i < projected.length; i += 1) {
      bytes += Buffer.byteLength(projected[i] ?? "", "utf8");
      if (i > 0) bytes += 1;
    }
    if (bytes > MAX_HASH_BYTES) {
      return { content_sha256: void 0, content_bytes: bytes, hash_skipped: true };
    }
    const hash = createHash2("sha256");
    for (let i = 0; i < projected.length; i += 1) {
      if (i > 0) hash.update("\n", "utf8");
      hash.update(projected[i] ?? "", "utf8");
    }
    return { content_sha256: hash.digest("hex"), content_bytes: bytes };
  } catch {
    return { content_sha256: void 0, content_bytes: 0, hash_skipped: true };
  }
}
function createTurnStore() {
  let record = { tool_calls: [], results: [] };
  const started = () => record.prompt !== void 0 || record.tool_calls.length > 0;
  function startTurn(sessionId, now) {
    if (record.session_id === void 0 && typeof sessionId === "string" && sessionId !== "") {
      record.session_id = sessionId;
    }
    if (record.started_at === void 0 && typeof now === "number" && Number.isFinite(now)) {
      record.started_at = now;
    }
  }
  return {
    startTurn,
    recordPrompt(text, sessionId, now = Date.now()) {
      try {
        startTurn(sessionId, now);
        record.prompt = typeof text === "string" ? text : "";
      } catch {
      }
    },
    recordToolCall(entry, sessionId, now = Date.now()) {
      try {
        if (entry === null || typeof entry !== "object") return;
        startTurn(sessionId, now);
        record.tool_calls.push({
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          decision: typeof entry.decision === "string" ? entry.decision : "",
          ts: now
        });
      } catch {
      }
    },
    /**
     * A result does **not** start a turn. A tool result whose call was never recorded belongs to a
     * turn already posted (or to one this process never saw), and starting a turn from it would post
     * a record with no prompt and no call — exactly the noise `PY:4975` refuses to send.
     */
    recordResult(entry) {
      try {
        if (entry === null || typeof entry !== "object") return;
        const stored = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          is_error: entry.is_error === true,
          content_bytes: typeof entry.content_bytes === "number" ? entry.content_bytes : 0
        };
        if (typeof entry.content_sha256 === "string") stored.content_sha256 = entry.content_sha256;
        if (entry.hash_skipped === true) stored.hash_skipped = true;
        record.results.push(stored);
      } catch {
      }
    },
    take() {
      try {
        if (!started()) return void 0;
        const taken = record;
        record = { tool_calls: [], results: [] };
        return taken;
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
        tool_calls: record.tool_calls.map((entry) => ({ ...entry })),
        results: record.results.map((entry) => ({ ...entry }))
      };
      if (record.prompt !== void 0) copy.prompt = record.prompt;
      if (record.session_id !== void 0) copy.session_id = record.session_id;
      if (record.started_at !== void 0) copy.started_at = record.started_at;
      return copy;
    }
  };
}
var turnStore = createTurnStore();

// packages/pi/src/agentEnd.ts
var TURNLOG_LABEL = "agent_end";
function handleAgentEnd(_event, ctx, deps) {
  try {
    const record = deps.store.take();
    if (!shouldPostTurn(record)) return void 0;
    const completedAtMs = (deps.now ?? Date.now)();
    let cwd = "";
    try {
      cwd = typeof ctx?.cwd === "string" ? ctx.cwd : "";
    } catch {
    }
    const body = buildTurnLogBody(record, { cwd, completedAtMs });
    const dispatchedAtMs = completedAtMs;
    void deps.client.postTurnLog(body).then((ok) => {
      if (ok) return;
      deps.telemetry?.reportBypass({
        errorClass: "TurnLogFailed",
        toolName: TURNLOG_LABEL,
        elapsedMs: (deps.now ?? Date.now)() - dispatchedAtMs,
        blocked: false
      });
    }).catch(() => {
    });
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
function noteDecision(deps, entry) {
  try {
    deps.onDecision?.(entry);
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
    const now = (deps.now ?? Date.now)();
    const state = deps.state ?? policyState;
    if (NATIVE_FILE_TOOLS.has(event.toolName) && shouldSkipFileToolFromState(event.toolName, state, now)) {
      noteDecision(deps, {
        tool_name: event.toolName,
        tool_use_id: event.toolCallId,
        decision: "skipped"
      });
      return void 0;
    }
    const pullPolicies = !areToolsFresh(state.getToolsSyncedAt(), now);
    const payload = buildPretoolPayload({
      toolName: event.toolName,
      command,
      toolUseId: event.toolCallId,
      toolInput,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      pullPolicies
    });
    const hooks = deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, event.toolName, hooks);
    noteDecision(deps, {
      tool_name: event.toolName,
      tool_use_id: event.toolCallId,
      decision: outcome.kind
    });
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
        const accepted = await confirmWithTimeout(
          ctx,
          CONFIRM_TITLE,
          reason + CONFIRM_QUESTION_SUFFIX
        );
        return accepted ? void 0 : { block: true, reason: DECLINED_REASON };
      }
      case "unavailable":
        return { block: true, reason: ENGINE_UNAVAILABLE_REASON };
    }
  } catch {
    return void 0;
  }
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
      hasUI: ctx.hasUI
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
        notifySafe(ctx, ENGINE_UNAVAILABLE_REASON, "error");
        return { action: "handled" };
      case "confirm":
        notifySafe(ctx, outcome.reason ?? GENERIC_DENY_REASON, "warning");
        deps.onPrompt?.(text);
        return void 0;
      case "allow":
        deps.onPrompt?.(text);
        return void 0;
      default:
        return void 0;
    }
  } catch {
    return void 0;
  }
}

// packages/pi/src/toolResult.ts
function recordToolResult(event, store) {
  try {
    const content = Array.isArray(event?.content) ? event.content : [];
    const hashed = hashContent(content);
    store.recordResult({
      tool_name: typeof event?.toolName === "string" ? event.toolName : "",
      tool_use_id: typeof event?.toolCallId === "string" ? event.toolCallId : "",
      is_error: event?.isError === true,
      ...hashed.content_sha256 === void 0 ? {} : { content_sha256: hashed.content_sha256 },
      content_bytes: hashed.content_bytes,
      ...hashed.hash_skipped === true ? { hash_skipped: true } : {}
    });
  } catch {
  }
  return void 0;
}

// packages/pi/src/userBash.ts
import { randomBytes as randomBytes2 } from "node:crypto";

// packages/pi/src/bashResult.ts
function denyBashResult(output) {
  return { result: { output, exitCode: 1, cancelled: false, truncated: false } };
}

// packages/pi/src/userBash.ts
function newUserBashId() {
  return USER_BASH_ID_PREFIX + randomBytes2(10).toString("hex");
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
      clientEntrypoint: deps.entrypoint
    });
    const hooks = deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, "bash", hooks);
    noteDecision(deps, { tool_name: "bash", tool_use_id: toolUseId, decision: outcome.kind });
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
        const accepted = await confirmWithTimeout(
          ctx,
          CONFIRM_TITLE,
          reason + CONFIRM_QUESTION_SUFFIX
        );
        return accepted ? void 0 : denyBashResult(DECLINED_REASON);
      }
      case "unavailable":
        return denyBashResult(ENGINE_UNAVAILABLE_REASON);
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
function versionOf(entrypoint) {
  const slash = entrypoint.indexOf("/");
  return slash === -1 ? entrypoint : entrypoint.slice(slash + 1);
}
var processHeartbeatGate = createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS });
function defaultMakeChecker(apiKey, baseUrl, env = {}, homeDir = "") {
  const client = createApiClient({ baseUrl, apiKey });
  const cachePath = resolveCachePath(env, homeDir);
  const fingerprint = keyFingerprint(apiKey);
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
    breaker: createBreaker({ now: Date.now }),
    keyState,
    onSync: cachePath === void 0 ? void 0 : (snapshot) => {
      void writeCache(cachePath, {
        ...snapshot,
        gateway_url: baseUrl,
        key_fingerprint: fingerprint
      });
    }
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
    heartbeatGate: overrides.heartbeatGate ?? processHeartbeatGate
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
        telemetry: client === void 0 ? void 0 : createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() })
      };
    }
    return resolved;
  }
  return (pi) => {
    pi.on("session_start", async (_event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === void 0 && !notified) {
          notified = true;
          notifySafe(ctx, NO_KEY_NOTICE, "info");
        }
        if (state.apiKey === void 0 || state.client === void 0) return void 0;
        if (keyState.isInactive()) return void 0;
        if (!deps.heartbeatGate.shouldSend(policyState.getFetchedAt())) return void 0;
        deps.heartbeatGate.markSent();
        const payload = buildHeartbeatPayload({
          cwd: safeCwd(ctx),
          sessionId: sessionIdOf(ctx),
          model: ctx.model?.id,
          clientEntrypoint: state.entrypoint,
          hasUI: ctx.hasUI === true,
          piVersion: versionOf(state.entrypoint)
        });
        const client = state.client;
        void client.postPretool(payload).then((result) => {
          if (result.ok) policyState.recordSuccess(result.body);
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
        return await decideToolCall(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          // Bound to the LIVE ctx at the registration, so 09-02's breaker-open and key-rejected
          // notices — raised deep inside `checkTool` — actually reach the editor on this path.
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          onDecision: (entry) => turnStore.recordToolCall(entry, sessionIdOf(ctx))
        });
      } catch {
        return void 0;
      }
    });
    pi.on("tool_result", async (event, _ctx) => {
      try {
        recordToolResult(event, turnStore);
      } catch {
      }
      return void 0;
    });
    pi.on("agent_end", (event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === void 0 || state.client === void 0) return void 0;
        if (keyState.isInactive()) {
          turnStore.take();
          return void 0;
        }
        return handleAgentEnd(event, ctx, {
          client: state.client,
          store: turnStore,
          ...state.telemetry === void 0 ? {} : { telemetry: state.telemetry }
        });
      } catch {
        return void 0;
      }
    });
    pi.on("user_bash", async (event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === void 0 || state.checker === void 0) return void 0;
        return await decideUserBash(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          onDecision: (entry) => turnStore.recordToolCall(entry, sessionIdOf(ctx))
        });
      } catch {
        return void 0;
      }
    });
    pi.on("input", async (event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === void 0 || state.checker === void 0) return void 0;
        return await decideInput(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The turn log's only source for the prompt: `agent_end.messages` is pi's `newMessages`
          // and never contains it (§A4). Called for an ALLOWED prompt only — a suppressed turn
          // produced nothing to log.
          onPrompt: (text) => turnStore.recordPrompt(text, sessionIdOf(ctx))
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
  defaultMakeChecker
};
