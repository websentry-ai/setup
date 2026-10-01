// The recording side of the opencode adapter: the `event` bus handler (and, below, the tool
// after-hook).
//
// The recording side never raises, never awaits on a decision path, and audits hash-only (pi
// parity; tool-output DLP is out of scope, as on pi). An `event` rejection is an unhandled rejection
// in the host that prints to the user's terminal (spike V1-4), so every handler here is total and
// awaits nothing: the bookkeeping is synchronous and every network call is fire-and-forget with a
// terminal catch.

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
