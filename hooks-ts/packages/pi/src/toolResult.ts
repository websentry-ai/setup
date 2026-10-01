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
// finishing and the model seeing its output. So: one hash and one capped text capture, no `await`,
// no filesystem, no network, no stderr — a size bail-out in `hashContent` for the 100 MB `read`
// (§F7), and a `captureText` that sizes before it copies and only ever copies the head and the tail.
// A grep of this file for either capability finds nothing, which is how the property is checked
// rather than asserted.
//
// **What is kept: a hash, and capped text.** `event.content` is hashed (every part), and its TEXT
// parts are captured at `MAX_TOOL_OUTPUT_CHARS`, both ends kept, so the turn log can carry the output
// for tool-output DLP and MCP output audit (HOOK-06's hash-only rule, reversed by user decision).
// Image parts are represented by the hash and byte count only; their base64 is never kept. The
// text is redacted before it is cut (head and tail windows wider than each cut, `captureText`), so a
// secret straddling a cut cannot survive in part; the per-turn budget and a second, post-time
// redaction happen downstream (`turn.ts`, `turnLog.ts`). `event.input` is not read at all: the
// call's input is recorded at the decision seam, already allowlisted.

import type { ToolResultEvent } from "@earendil-works/pi-coding-agent";

import { MAX_TOOL_OUTPUT_CHARS } from "../../core/src/constants.ts";
import { captureText, hashContent } from "../../core/src/turn.ts";
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
export function recordToolResult(
  event: ToolResultLike,
  store: TurnStore,
  /**
   * Scrub secrets from the captured text BEFORE it is cut (see `captureText`): the composition root
   * binds it to `redactSecrets` and the session key. Optional so a test can capture raw text.
   */
  redact?: (text: string) => string,
): undefined {
  try {
    const content = Array.isArray(event?.content) ? event.content : [];
    const hashed = hashContent(content);
    // Text parts only, capped at both ends; `undefined` for an output with no text (all images).
    // Hash and byte count above are over the ORIGINAL content; only the kept text is redacted.
    const captured = captureText(content, MAX_TOOL_OUTPUT_CHARS, redact);
    store.recordResult({
      tool_name: typeof event?.toolName === "string" ? event.toolName : "",
      tool_use_id: typeof event?.toolCallId === "string" ? event.toolCallId : "",
      is_error: event?.isError === true,
      ...(hashed.content_sha256 === undefined ? {} : { content_sha256: hashed.content_sha256 }),
      content_bytes: hashed.content_bytes,
      ...(hashed.hash_skipped === true ? { hash_skipped: true as const } : {}),
      ...(captured === undefined ? {} : { content: captured.text }),
      ...(captured?.truncated === true ? { content_truncated: true as const } : {}),
      ...(captured?.original_chars === undefined ? {} : { content_original_chars: captured.original_chars }),
    });
  } catch {
    // `emitToolResult` catches and reports handler exceptions without rethrowing, so a throw here
    // would be fail-open by pi's design anyway — but a missing audit line is a better outcome than
    // a reported extension error on every tool call.
  }
  return undefined;
}
