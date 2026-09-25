// The pretool payload builder — a pure function. No fetch, no fs, no logging, and nothing is ever
// written to disk (ASVS V8 / T-08-12): the body carries the verbatim shell command and cwd.
//
// Two contracts live here:
//
//   * The §B1 field list, exactly. Every Phase-9 / Future field is absent from the code as well as
//     the type — the identity field in particular runs a deny-capable gate server-side.
//   * The path contract carried forward from the Phase-7 review (STATE.md): pi makes `path`
//     OPTIONAL on grep/find/ls (§A2), while the API entry gate requires
//     `!!command || (isValidNativeTool && !!filePath)` (§B3). A pathless search would therefore
//     skip policy evaluation entirely, so those three tools always send `metadata.file_path`,
//     defaulting to cwd.

import { APP_LABEL, EVENT_NAME_TOOL_USE, MAX_COMMAND_CHARS, MAX_TOOL_INPUT_BYTES } from "./constants.ts";
import type { PreToolUseData, PretoolPayloadInput, PretoolRequestBody } from "./types.ts";

/** Native search tools whose `path` is optional in pi — `file_path` falls back to cwd. */
export const PATH_DEFAULTING_TOOLS = ["grep", "find", "ls"] as const;
/** Native file tools whose `path` is required by pi's schema. */
export const PATH_REQUIRED_TOOLS = ["read", "write", "edit"] as const;

const PATH_DEFAULTING: ReadonlySet<string> = new Set(PATH_DEFAULTING_TOOLS);
const PATH_REQUIRED: ReadonlySet<string> = new Set(PATH_REQUIRED_TOOLS);

/**
 * `metadata.file_path` for a tool call, or `undefined` when the tool has no file semantics
 * (`bash`, `powershell`, any custom/MCP tool) — those are evaluated on `command`.
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

/** Assemble the §B1 body. Pure: same input, same output, no side effects. */
export function buildPretoolPayload(input: PretoolPayloadInput): PretoolRequestBody {
  const metadata: Record<string, unknown> = {
    cwd: input.cwd,
    tool_input: capToolInput(input.toolInput),
  };
  const filePath = resolveFilePath(input.toolName, input.toolInput, input.cwd);
  if (filePath !== undefined) metadata.file_path = filePath;

  const preToolUseData: PreToolUseData = {
    // Forwarded verbatim: Phase 7 registered the lowercase pi names, so title-casing means the
    // server never matches the tool and enforcement silently disappears.
    tool_name: input.toolName,
    command: input.command.length > MAX_COMMAND_CHARS ? input.command.slice(0, MAX_COMMAND_CHARS) : input.command,
    metadata,
  };
  if (typeof input.toolUseId === "string" && input.toolUseId.length > 0) {
    preToolUseData.tool_use_id = input.toolUseId;
  }

  return {
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
}
