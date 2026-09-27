// HOOK-06 — the `tool_result` adapter. It exists to record four facts about a tool result and to
// return nothing.
//
// **The return value is the security contract.** `agent-session.js:265-294` installs
// `agent.afterToolCall`, awaits `runner.emitToolResult(...)` and then folds any defined field of the
// handler result back into the real result the model reads:
//
//     return { content: normalizedContent, details: hookResult?.details,
//              isError: hookResult?.isError ?? isError, usage: hookResult?.usage };
//
// So `{}` is safe only by accident (`if (!handlerResult) continue` treats it as truthy but it sets no
// field) and a single stray `isError: false` would silently turn a failed tool into a successful one.
// This handler therefore returns the literal `undefined`, and `toolResult.test.ts` asserts it with
// `assert.strictEqual`, never a truthiness check.
//
// **It is on an awaited path.** Registering any `tool_result` handler switches on an extra awaited
// pass for every tool result (`agent-session.js:267`, the `hasHandlers` gate), between the tool
// finishing and the model seeing its output. So: one hash, no `await`, no `node:fs`, no `fetch`, no
// stderr — and a size bail-out in `hashContent` for the 100 MB `read` (§F7).
//
// **The raw content is read once and dropped.** `event.content` is projected, hashed and forgotten;
// `event.input` is not read at all, because the turn log sends `tool_input: {}` and reaching for it
// here would re-open the egress that 09-02's allowlist closed.

import type { ToolResultEvent } from "@earendil-works/pi-coding-agent";

import { hashContent } from "../../core/src/turn.ts";
import type { TurnStore } from "../../core/src/turn.ts";

/**
 * The structural slice this adapter reads. `toolName` is declared here because it lives on each
 * VARIANT of pi's union rather than on `ToolResultEventBase` (`types.d.ts:791-836`) — the same reason
 * `ToolCallLike` declares it.
 */
export interface ToolResultLike {
  toolCallId: string;
  toolName: string;
  content: readonly unknown[];
  isError: boolean;
}

/**
 * Drift alarm, as in `narrow.ts`: pi's real event union must stay assignable to the slice above. A
 * renamed `toolCallId` or a `content` that stops being an array resolves this to `never` and fails
 * `npm run typecheck`, rather than silently recording empty hashes for every tool in the session.
 */
export type ToolResultEventIsCompatible = ToolResultEvent extends ToolResultLike ? true : never;

/**
 * Record one tool result and return `undefined`.
 *
 * `store` is a parameter rather than the module singleton so a test can hand in a fresh store (and a
 * throwing one). The `try` opens before the first statement: a malformed event, a hostile getter or a
 * store fault must all produce the same silent no-op.
 */
export function recordToolResult(event: ToolResultLike, store: TurnStore): undefined {
  try {
    const content = Array.isArray(event?.content) ? event.content : [];
    const hashed = hashContent(content);
    store.recordResult({
      tool_name: typeof event?.toolName === "string" ? event.toolName : "",
      tool_use_id: typeof event?.toolCallId === "string" ? event.toolCallId : "",
      is_error: event?.isError === true,
      ...(hashed.content_sha256 === undefined ? {} : { content_sha256: hashed.content_sha256 }),
      content_bytes: hashed.content_bytes,
      ...(hashed.hash_skipped === true ? { hash_skipped: true as const } : {}),
    });
  } catch {
    // `emitToolResult` catches and reports handler exceptions without rethrowing, so a throw here
    // would be fail-open by pi's design anyway — but a missing audit line is a better outcome than
    // a reported extension error on every tool call.
  }
  return undefined;
}
