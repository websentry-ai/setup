// The one place this package raises an error on purpose.
//
// On opencode v1, raising from `tool.execute.before` IS the deny mechanism: the host turns the error
// into a failed tool part and hands `error.message` to the model as the tool's error text
// (`oc:opencode/src/plugin/index.ts:284-297`, `oc:opencode/src/session/processor.ts:186-205`,
// `message-v2.ts:342-347`). The flip side is that ANY accidental raise from a handler is a
// model-visible deny. So every deliberate block funnels through this one function, a source test
// (`test/throwSites.test.ts`) keeps it the only raise site in the package and restricts who may call
// it, and every caller passes a message produced by core's `verdictMessage` or this package's verdict
// helpers.
//
// Spike V1-1 (13-SPIKES.md): the model receives the message verbatim, with no `Error:` or wrapper
// prefix, so the text is used as is.
//
// `stack` is replaced by the message. On the `chat.message` path the host prints `Cause.pretty`,
// which includes the stack, to `session.error` consumers (V1-5); a stack would leak the plugin's file
// path and frames there. On the tool path only `message` is read, so this changes nothing there.

import { GENERIC_DENY_REASON } from "../../core/src/constants.ts";

export function block(message: string): never {
  const text = typeof message === "string" && message.length > 0 ? message : GENERIC_DENY_REASON;
  const err = new Error(text);
  try {
    err.stack = text;
  } catch {
    // A frozen Error prototype is not worth losing the block over.
  }
  throw err;
}
