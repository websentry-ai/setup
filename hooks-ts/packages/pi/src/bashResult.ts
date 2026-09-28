// The ONE constructor for pi's `BashResult`. Nothing else in this package may build that object.
//
// `UserBashEventResult` is `{operations} | {result: BashResult}` — there is no `block` field — and
// the runner validates the return at runtime before using it:
//
//   // PI/dist/core/extensions/runner.js:51-74  isUserBashEventResult
//   if (hasOperations === hasResult) return false;        // exactly one arm, never both
//   return (typeof resultRecord.output === "string" &&
//           "exitCode" in resultRecord &&                 // ← KEY PRESENCE, not a value check
//           (resultRecord.exitCode === undefined || typeof resultRecord.exitCode === "number") &&
//           typeof resultRecord.cancelled === "boolean" &&
//           typeof resultRecord.truncated === "boolean" && …);
//
//   // PI/dist/core/extensions/runner.js:876-878  emitUserBash
//   if (!isUserBashEventResult(handlerResult)) throw new Error("Invalid user_bash handler result: …");
//
// and that throw is **rethrown** out of `emitUserBash`, whereupon `interactive-mode.js:5656-5666`
// gives up without running the command and without rendering anything. So a missing key here is not
// a cosmetic bug — it silently swallows whatever the developer typed. Hence: four keys, written
// literally, in one place, with the return type taken from pi itself so `npm run typecheck` fails if
// a future release changes the shape.
//
// `fullOutputPath` is deliberately never set: it is a path to a temp file holding full output, and we
// have no output — only a reason.

import type { UserBashEventResult } from "@earendil-works/pi-coding-agent";

/**
 * A synthetic result standing in for a command that was not run. `output` is the reason the user and
 * (unless `!!` was typed) the model will read; pi renders it under the command and passes it to
 * `recordBashResult`, so it is already core-sanitised guardrail text by the time it arrives here.
 *
 * `exitCode: 1` rather than `undefined`: `undefined` is pi's encoding for "killed or cancelled", and
 * a policy decision is a failure with a reason, not a cancellation.
 */
export function denyBashResult(output: string): UserBashEventResult {
  return { result: { output, exitCode: 1, cancelled: false, truncated: false } };
}
