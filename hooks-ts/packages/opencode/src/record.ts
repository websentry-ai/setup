// The recording side of the opencode adapter: the `event` bus handler (and, below, the tool
// after-hook).
//
// The recording side never raises, never awaits on a decision path, and audits hash-only (pi
// parity; tool-output DLP is out of scope, as on pi). An `event` rejection is an unhandled rejection
// in the host that prints to the user's terminal (spike V1-4), so every handler here is total and
// awaits nothing: the bookkeeping is synchronous and every network call is fire-and-forget with a
// terminal catch.

import { hashContent } from "../../core/src/turn.ts";
import { SIGNAL_ARGS_CHANGED } from "./constants.ts";
import { argsDigest } from "./narrow.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";

export interface RecordContext {
  runtime: Runtime;
  record: DirectoryRecord;
}

function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function readString(value: unknown, key: string): string {
  const field = readField(value, key);
  return typeof field === "string" ? field : "";
}

/** The longest scalar tool output turned into text before hashing (a non-string, non-MCP output). */
const MAX_SCALAR_OUTPUT_CHARS = 64;

/**
 * The content parts a tool output is hashed over: a string is one text part; an MCP
 * `CallToolResult` (`{content: [...]}`) is its content array; a number or boolean is its short text;
 * anything else is nothing. Total.
 */
export function outputParts(output: unknown): unknown[] {
  try {
    if (typeof output === "string") return [{ type: "text", text: output }];
    if (typeof output === "number" || typeof output === "boolean") {
      return [{ type: "text", text: String(output).slice(0, MAX_SCALAR_OUTPUT_CHARS) }];
    }
    const content = readField(output, "content");
    return Array.isArray(content) ? content : [];
  } catch {
    return [];
  }
}

/** Record one result for a call, once per callID, hash-only. Total. */
function recordResult(ctx: RecordContext, sessionID: string, callID: string, tool: string, isError: boolean, parts: unknown[]): void {
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
      ...(hashed.content_sha256 === undefined ? {} : { content_sha256: hashed.content_sha256 }),
      content_bytes: hashed.content_bytes,
      ...(hashed.hash_skipped === true ? { hash_skipped: true as const } : {}),
    });
  } catch {
    // A missing audit line, never a fault.
  }
}

/**
 * HOOK-18: did another plugin change this call's args after our check? Detection only, never a
 * block (Pitfall 5): the call already ran. A call we never stored a digest for (not checked, or
 * blocked) is not compared.
 */
function checkTamper(ctx: RecordContext, sessionID: string, callID: string, tool: string, args: unknown): void {
  try {
    const { runtime } = ctx;
    const before = runtime.takeDigest(sessionID, callID);
    if (before === undefined) return;
    const now = argsDigest(args);
    if (now === before) return;
    runtime.reportSignal(SIGNAL_ARGS_CHANGED, tool, now === undefined ? "digest_unavailable" : "digest_mismatch");
  } catch {
    // ditto
  }
}

/** `message.part.updated` for a tool part: the error-path audit (HOOK-15). */
function onToolPart(sessionID: string, part: unknown, ctx: RecordContext): void {
  const state = readField(part, "state");
  if (readField(state, "status") !== "error") return;
  const callID = readString(part, "callID");
  const tool = readString(part, "tool");
  const error = readField(state, "error");
  recordResult(ctx, sessionID, callID, tool, true, [{ type: "text", text: typeof error === "string" ? error : "" }]);
}

/** `message.part.updated`: dispatch by part type. */
function onPartUpdated(properties: unknown, ctx: RecordContext): void {
  const part = readField(properties, "part");
  const sessionID = readString(properties, "sessionID") || readString(part, "sessionID");
  if (sessionID === "") return;
  switch (readField(part, "type")) {
    case "tool":
      onToolPart(sessionID, part, ctx);
      return;
    default:
      return;
  }
}

/** `session.created`: remember the parent of a child session. */
function onSessionCreated(properties: unknown, ctx: RecordContext): void {
  const info = readField(properties, "info");
  const sessionID = readString(properties, "sessionID") || readString(info, "id");
  if (sessionID === "") return;
  ctx.runtime.setParent(sessionID, readField(info, "parentID"));
}

/** Handle one bus event synchronously. Total. */
export function handleEvent(input: unknown, ctx: RecordContext): void {
  try {
    const event = readField(input, "event");
    const type = readString(event, "type");
    const properties = readField(event, "properties");
    switch (type) {
      case "session.created":
        onSessionCreated(properties, ctx);
        return;
      case "message.part.updated":
        onPartUpdated(properties, ctx);
        return;
      default:
        return;
    }
  } catch {
    // An event we cannot read is an event we ignore.
  }
}

/** The registered `event` handler. Never rejects (V1-4). */
export function eventHandler(ctx: RecordContext): (input: unknown) => Promise<void> {
  return async (input: unknown): Promise<void> => {
    try {
      handleEvent(input, ctx);
    } catch {
      // Never reject from `event`.
    }
  };
}

/**
 * `tool.execute.after` (success only, `oc:opencode/src/session/tools.ts:121-125`): the hash-only
 * audit of the result, then the args tamper comparison. Always resolves `undefined`; the output object
 * is only read, never written.
 */
export function toolExecuteAfter(ctx: RecordContext): (input: unknown, output: unknown) => Promise<void> {
  return async (input: unknown, output: unknown): Promise<void> => {
    try {
      const tool = readString(input, "tool");
      const sessionID = readString(input, "sessionID");
      const callID = readString(input, "callID");
      recordResult(ctx, sessionID, callID, tool, false, outputParts(readField(output, "output")));
      checkTamper(ctx, sessionID, callID, tool, readField(input, "args"));
    } catch {
      // Never raise from the after-hook.
    }
  };
}
