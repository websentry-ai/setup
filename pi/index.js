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
var APP_LABEL = "pi";
var HOOK_SOURCE = "pi";
var EVENT_NAME_TOOL_USE = "tool_use";
var PRETOOL_PATH = "/v1/hooks/pretool";
var ERRORS_PATH = "/v1/hooks/errors";
var PRETOOL_TIMEOUT_MS = 2e4;
var ERRORS_TIMEOUT_MS = 1e4;
var CONFIRM_TIMEOUT_MS = 12e4;
var ERROR_REPORT_INTERVAL_MS = 6e4;
var ERROR_CATEGORY_BYPASS = "bypassed_due_to_failure";
var MAX_REASON_CHARS = 2e3;
var MAX_TOOL_INPUT_BYTES = 16384;
var MAX_COMMAND_CHARS = 8192;
var DENY_PREFIX = "Blocked by Unbound policy: ";
var GENERIC_DENY_REASON = "Blocked by Unbound policy.";
var DECLINED_REASON = "Declined by user (Unbound policy)";
var CONFIRM_TITLE = "Unbound policy";
var CONFIRM_QUESTION_SUFFIX = "\n\nRun this command?";
var NO_UI_REASON = "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
var ENGINE_UNAVAILABLE_REASON = "Unbound policy engine unavailable \u2014 please retry";
var NO_KEY_NOTICE = "Unbound: no API key found \u2014 extension inactive";

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
  return { postPretool, postHookErrors };
}

// packages/core/src/config.ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function readUnboundConfig(homeDir) {
  try {
    const raw = readFileSync(join(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed;
  } catch {
    return {};
  }
}
function usableString(candidate) {
  return typeof candidate === "string" && candidate.trim().length > 0 ? candidate : void 0;
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
    const url = new URL(candidate.trim());
    const isLoopbackHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !isLoopbackHttp) return void 0;
    return url.origin;
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

// packages/core/src/piVersion.ts
import { readFileSync as readFileSync2 } from "node:fs";
import { dirname, join as join2 } from "node:path";
var PI_PACKAGE_NAME = ["@earendil", "-works", "/pi-coding-agent"].join("");
var MAX_WALK_UP_LEVELS = 8;
var MAX_VERSION_CHARS = 32;
function readManagedInstallVersion(env) {
  const root = env[ENV_PI_INSTALL_ROOT];
  if (typeof root !== "string" || root.length === 0) return void 0;
  try {
    const version = readFileSync2(join2(root, "current-version"), "utf8").trim();
    return version.length > 0 ? version : void 0;
  } catch {
    return void 0;
  }
}
function readVersionFromArgv(argv1) {
  if (typeof argv1 !== "string" || argv1.length === 0) return void 0;
  let dir = dirname(argv1);
  for (let level = 0; level < MAX_WALK_UP_LEVELS; level += 1) {
    try {
      const parsed = JSON.parse(readFileSync2(join2(dir, "package.json"), "utf8"));
      if (parsed !== null && typeof parsed === "object") {
        const pkg = parsed;
        if (pkg.name === PI_PACKAGE_NAME && typeof pkg.version === "string" && pkg.version.length > 0) {
          return pkg.version;
        }
      }
    } catch {
    }
    const parent = dirname(dir);
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
var CONTROL_CHARS = /[\x00-\x09\x0b-\x1f\x7f]/g;
function parseDecision(raw) {
  if (raw === "allow" || raw === "deny" || raw === "ask" || raw === "approval_required") {
    return raw;
  }
  return void 0;
}
function sanitizeReason(raw) {
  if (typeof raw !== "string") return void 0;
  const stripped = raw.replace(CONTROL_CHARS, "");
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
function createPolicyChecker(opts) {
  async function checkTool(payload, toolName) {
    try {
      const res = await opts.client.postPretool(payload);
      if (res.ok) {
        opts.state.recordSuccess(res.body);
        return mapResponseToOutcome(res.body);
      }
      opts.telemetry.reportBypass({
        errorClass: res.errorClass,
        toolName,
        elapsedMs: res.elapsedMs
      });
      return opts.state.getFailureAction() === "block" ? { kind: "unavailable" } : { kind: "allow" };
    } catch {
      return { kind: "allow" };
    }
  }
  return { checkTool };
}

// packages/core/src/policyState.ts
function parseFailureAction(raw) {
  return raw === "allow" || raw === "block" ? raw : void 0;
}
function parseToolsToCheck(raw) {
  if (!Array.isArray(raw)) return void 0;
  const tools = raw.filter((entry) => typeof entry === "string");
  return tools.length > 0 ? tools : void 0;
}
function createPolicyState() {
  let failureAction;
  let toolsToCheck;
  return {
    recordSuccess(body) {
      const nextAction = parseFailureAction(body.policy_check_failure_action);
      if (nextAction !== void 0) failureAction = nextAction;
      const nextTools = parseToolsToCheck(body.tools_to_check);
      if (nextTools !== void 0) toolsToCheck = nextTools;
    },
    getFailureAction: () => failureAction,
    getToolsToCheck: () => toolsToCheck
  };
}
var policyState = createPolicyState();

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
      if (reporting) return;
      const at = now();
      if (lastReportAtMs !== void 0 && at - lastReportAtMs < intervalMs) return;
      lastReportAtMs = at;
      reporting = true;
      const message = redactSecrets(
        `pi hook ${ERROR_CATEGORY_BYPASS}: ${ctx.errorClass} for tool=${ctx.toolName} after ${ctx.elapsedMs}ms`,
        apiKey
      );
      const body = {
        errors: [
          { message, timestamp: new Date(at).toISOString(), category: ERROR_CATEGORY_BYPASS }
        ],
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

// packages/core/src/payload.ts
var PATH_DEFAULTING_TOOLS = ["grep", "find", "ls"];
var PATH_REQUIRED_TOOLS = ["read", "write", "edit"];
var PATH_DEFAULTING = new Set(PATH_DEFAULTING_TOOLS);
var PATH_REQUIRED = new Set(PATH_REQUIRED_TOOLS);
function resolveFilePath(toolName, toolInput, cwd) {
  const isDefaulting = PATH_DEFAULTING.has(toolName);
  if (!isDefaulting && !PATH_REQUIRED.has(toolName)) return void 0;
  const path = toolInput.path;
  if (typeof path === "string" && path.length > 0) return path;
  return isDefaulting ? cwd : void 0;
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
function buildPretoolPayload(input) {
  const metadata = {
    cwd: input.cwd,
    tool_input: capToolInput(input.toolInput)
  };
  const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd);
  if (filePath !== void 0) metadata.file_path = filePath;
  const preToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears.
    tool_name: input.toolName,
    command: input.command.length > MAX_COMMAND_CHARS ? input.command.slice(0, MAX_COMMAND_CHARS) : input.command,
    metadata
  };
  if (typeof input.toolUseId === "string" && input.toolUseId.length > 0) {
    preToolUseData.tool_use_id = input.toolUseId;
  }
  return {
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
}

// packages/pi/src/narrow.ts
function isBashCall(e) {
  return e.toolName === "bash" && typeof e.input.command === "string";
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
async function decideToolCall(event, ctx, deps) {
  try {
    const bash = isBashCall(event);
    const command = bash ? event.input.command : "";
    if (bash && command.trim() === "") return void 0;
    const payload = buildPretoolPayload({
      toolName: event.toolName,
      command,
      toolUseId: event.toolCallId,
      toolInput: event.input ?? {},
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint
    });
    const outcome = await deps.checker.checkTool(payload, event.toolName);
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

// packages/pi/src/index.ts
function defaultMakeChecker(apiKey, baseUrl) {
  const client = createApiClient({ baseUrl, apiKey });
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey })
  });
}
function safeHomeDir() {
  try {
    return homedir();
  } catch {
    return "";
  }
}
function createExtension(overrides = {}) {
  const deps = {
    env: overrides.env ?? process.env,
    homeDir: overrides.homeDir ?? safeHomeDir(),
    makeChecker: overrides.makeChecker ?? defaultMakeChecker,
    entrypoint: overrides.entrypoint
  };
  let resolved;
  let notified = false;
  function init() {
    if (resolved === void 0) {
      const apiKey = resolveApiKey(deps.env, deps.homeDir);
      resolved = {
        apiKey,
        entrypoint: deps.entrypoint ?? resolveClientEntrypoint(deps.env, process.argv[1]),
        checker: apiKey === void 0 ? void 0 : deps.makeChecker(apiKey, resolveGatewayUrl(deps.env, deps.homeDir))
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
          entrypoint: state.entrypoint
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
  index_default as default
};
