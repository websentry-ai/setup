// The recording side of the opencode adapter: the `event` bus handler (and, below, the tool
// after-hook).
//
// The recording side never raises, never awaits on a decision path, and audits hash-only (pi
// parity; tool-output DLP is out of scope, as on pi). An `event` rejection is an unhandled rejection
// in the host that prints to the user's terminal (spike V1-4), so every handler here is total and
// awaits nothing: the bookkeeping is synchronous and every network call is fire-and-forget with a
// terminal catch.

import { buildHeartbeatPayload } from "../../core/src/heartbeat.ts";
import { directoryKey } from "../../core/src/sessionState.ts";
import { hashContent } from "../../core/src/turn.ts";
import { buildTurnLogBody, shouldPostTurn } from "../../core/src/turnLog.ts";
import { SIGNAL_ARGS_CHANGED } from "./constants.ts";
import { argsDigest } from "./narrow.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { OPENCODE_PROFILE } from "./profile.ts";

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

/**
 * HOOK-19 (V1-7): a bash part's command, stashed synchronously by callID so `shell.env` (which gets
 * no command) can check a user `!cmd`. The user shell persists the part before `shell.env` fires;
 * a final status drops the stash. `shell.env` reports `SIGNAL_USER_SHELL_UNCHECKED` when it finds
 * nothing to check.
 */
function stashBash(sessionID: string, part: unknown, state: unknown, ctx: RecordContext): void {
  try {
    const callID = readString(part, "callID");
    const status = readField(state, "status");
    if (status === "completed" || status === "error") {
      ctx.runtime.dropUserShell(sessionID, callID);
      return;
    }
    ctx.runtime.stashUserShell(sessionID, callID, readString(readField(state, "input"), "command"));
  } catch {
    // Missing stash = `no_part` at `shell.env` time.
  }
}

/** `message.part.updated` for a tool part: the bash stash (HOOK-19), then the error-path audit (HOOK-15). */
function onToolPart(sessionID: string, part: unknown, ctx: RecordContext): void {
  const state = readField(part, "state");
  const tool = readString(part, "tool");
  if (tool === "bash") stashBash(sessionID, part, state, ctx);
  if (readField(state, "status") !== "error") return;
  const callID = readString(part, "callID");
  const error = readField(state, "error");
  recordResult(ctx, sessionID, callID, tool, true, [{ type: "text", text: typeof error === "string" ? error : "" }]);
}

/** `message.part.updated` for a text part: keep the latest text of a non-synthetic assistant part. */
function onTextPart(sessionID: string, part: unknown, ctx: RecordContext): void {
  const { runtime } = ctx;
  if (readField(part, "synthetic") === true) return;
  // Child (subagent) text is not the root's answer, and a child idle posts nothing.
  if (runtime.isChild(sessionID)) return;
  if (!runtime.recordingActive()) return;
  const messageID = readString(part, "messageID");
  if (runtime.roleOf(sessionID, messageID) !== "assistant") return;
  const partID = readString(part, "id");
  const text = readField(part, "text");
  if (partID === "" || typeof text !== "string") return;
  runtime.setAssistantPart(sessionID, partID, text);
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
    case "text":
      onTextPart(sessionID, part, ctx);
      return;
    default:
      return;
  }
}

/** `info.version` if it is a plain version token, else `undefined` (T-13-33). */
export function sanitizeHostVersion(value: unknown): string | undefined {
  return typeof value === "string" && /^[0-9A-Za-z.+-]{1,64}$/.test(value) ? value : undefined;
}

/**
 * The heartbeat for a new root session: once per directory per TTL, fire-and-forget, mirroring pi's
 * `session_start` (warm the policy metadata, then persist it through the identity-bound cache).
 */
function sendHeartbeat(sessionID: string, info: unknown, version: string | undefined, ctx: RecordContext): void {
  const { runtime, record } = ctx;
  if (!runtime.recordingActive()) return;
  const resolved = runtime.init();
  const client = resolved.client;
  const scope = resolved.scope;
  if (client === undefined || scope === undefined) return;
  const directory = directoryKey(readField(info, "directory")) ?? record.directory;
  const gate = runtime.instances.forDirectory(directory).heartbeatGate;
  if (!gate.shouldSend(scope.policy.getFetchedAt())) return;
  // Claimed before dispatch: two creations in the same tick must not both get through.
  gate.markSent();
  const identity = runtime.identity();
  const body = buildHeartbeatPayload(
    {
      cwd: directory,
      sessionId: sessionID,
      model: undefined,
      clientEntrypoint: runtime.entrypoint(),
      hasUI: false,
      agentVersion: version ?? "unknown",
      ...(identity === undefined ? {} : { accountIdentity: identity }),
    },
    OPENCODE_PROFILE,
  );
  void Promise.resolve()
    .then(() => client.postPretool(body))
    .then((result) => {
      if (!result.ok) return;
      scope.policy.recordSuccess(result.body);
      try {
        resolved.cacheSync?.(scope.policy.snapshot());
      } catch {
        // A cache we could not write costs one round trip next time.
      }
    })
    .catch(() => {
      // A failed heartbeat is a cache miss, never a block and never a notice.
    });
}

/** `session.created`: parent map, host version, and the root heartbeat. */
function onSessionCreated(properties: unknown, ctx: RecordContext): void {
  const { runtime } = ctx;
  const info = readField(properties, "info");
  const sessionID = readString(properties, "sessionID") || readString(info, "id");
  if (sessionID === "") return;
  runtime.setParent(sessionID, readField(info, "parentID"));
  const version = sanitizeHostVersion(readField(info, "version"));
  // Process-wide: one opencode binary serves every directory. A bad value never replaces a good one.
  if (version !== undefined) runtime.hostVersion = version;
  if (runtime.isChild(sessionID)) return;
  sendHeartbeat(sessionID, info, version, ctx);
}

/** `message.updated`: remember the message's role, so its text parts can be attributed. */
function onMessageUpdated(properties: unknown, ctx: RecordContext): void {
  const info = readField(properties, "info");
  const sessionID = readString(properties, "sessionID") || readString(info, "sessionID");
  ctx.runtime.setRole(sessionID, readString(info, "id"), readString(info, "role"));
}

/**
 * `session.idle`: one turn log per root turn (12-03: post before any release). A child idle posts
 * nothing; its calls were recorded into the root's turn. Dispatched, never awaited.
 */
function onSessionIdle(properties: unknown, ctx: RecordContext): void {
  const { runtime, record } = ctx;
  const sessionID = readString(properties, "sessionID");
  if (sessionID === "" || runtime.isChild(sessionID)) return;
  // Taken unconditionally: a record nothing will post must not linger.
  const turn = runtime.sessions.forSession(sessionID).turn.take();
  const assistantText = runtime.takeAssistantText(sessionID);
  if (!runtime.recordingActive() || !shouldPostTurn(turn)) return;
  const resolved = runtime.init();
  const client = resolved.client;
  if (client === undefined || turn === undefined) return;
  const now = runtime.deps.now;
  const completedAtMs = now();
  const identity = runtime.identity();
  const body = buildTurnLogBody(turn, {
    cwd: record.directory,
    completedAtMs,
    assistantText,
    ...(resolved.apiKey === undefined ? {} : { apiKey: resolved.apiKey }),
    ...(identity === undefined ? {} : { accountIdentity: identity }),
  });
  void Promise.resolve()
    .then(() => client.postTurnLog(body))
    .then((ok) => {
      if (ok) return;
      resolved.telemetry?.reportTurnLogFailure({
        errorClass: "TurnLogFailed",
        toolName: "session.idle",
        elapsedMs: now() - completedAtMs,
      });
    })
    .catch(() => {
      // Never an unhandled rejection in the host.
    });
}

/** `session.deleted`: release every per-session store. Dropped state is never posted (12-03). */
function onSessionDeleted(properties: unknown, ctx: RecordContext): void {
  const info = readField(properties, "info");
  const sessionID = readString(properties, "sessionID") || readString(info, "id");
  ctx.runtime.releaseSession(sessionID);
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
