// A local `bash` type guard.
//
// pi exports a ready-made narrowing helper for tool-call events, but it is a **runtime value**
// export: importing it would make esbuild follow `@earendil-works/pi-coding-agent` into the whole
// coding agent, TUI, providers and undici, turning a few-KB extension into a multi-MB bundle whose
// own bare specifiers cannot resolve under pi's jiti loader (§F6 / §A9). So the pi package is
// referenced here by `import type` only — those imports vanish at compile time — and the three-line
// equivalent lives below.
//
// A bare `event.toolName === "bash"` check does NOT narrow on its own, because
// `CustomToolCallEvent.toolName` is `string` and overlaps every literal in the union (§A10); the
// `input.command` probe is what makes the predicate sound.

import type { ToolCallEvent } from "@earendil-works/pi-coding-agent";

/** The structural slice of a tool-call event this package reads. */
export interface ToolCallLike {
  toolName: string;
  toolCallId: string;
  input: unknown;
}

/**
 * Drift alarm: pi's real event union must stay assignable to `ToolCallLike`. If a future pi release
 * renames `toolCallId` or `toolName`, `npm run typecheck` resolves this to `never` and fails.
 */
export type ToolCallEventIsCompatible = ToolCallEvent extends ToolCallLike ? true : never;

/** pi's `bash` tool input (`tools/bash.js:26-29`). */
export interface BashInput {
  command: string;
  timeout?: number;
}

export function isBashCall<T extends ToolCallLike>(e: T): e is T & { input: BashInput } {
  return e.toolName === "bash" && typeof (e.input as { command?: unknown }).command === "string";
}
