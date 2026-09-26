// The verdict-to-pi-behaviour mapping: one `PolicyOutcome` in, one `ToolCallEventResult` (or
// nothing) out.
//
// What the developer and the model see is decided entirely here, so three rules are load-bearing:
//
//   1. **The API reason is concatenated, never reformatted.** `{block:true, reason}` makes `reason`
//      the error tool-result content the model reads (§B5). Core has already enum-validated,
//      control-stripped and length-capped it; appending it after a literal prefix keeps it quoted
//      guardrail text and keeps the gateway's attribution footer last (T-08-02).
//   2. **No UI means no question.** A verdict needing confirmation blocks when `ctx.hasUI` is false;
//      there is nobody to ask and `noOpUIContext.confirm` would silently answer `false` anyway (§A6).
//   3. **`event.input` is never written.** pi permits mutation but re-validates nothing afterwards
//      (`types.d.ts:788`), and Phase 8 has no reason to patch arguments (§F9).
//
// Every user-facing string comes from `constants.ts`; none is retyped here.

import {
  CONFIRM_QUESTION_SUFFIX,
  CONFIRM_TITLE,
  DECLINED_REASON,
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  GENERIC_DENY_REASON,
  NO_UI_REASON,
} from "../../core/src/constants.ts";
import { buildPretoolPayload } from "../../core/src/payload.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { isShellCall } from "./narrow.ts";
import type { ToolCallLike } from "./narrow.ts";
import { confirmWithTimeout, notifySafe } from "./ui.ts";
import type { UiCtx } from "./ui.ts";

/** The structural slice of `ExtensionContext` a decision needs (§A4). */
export interface DecideCtx extends UiCtx {
  cwd: string;
  sessionManager: { getSessionId(): string };
  /** `Model | undefined` in pi — the payload builder substitutes `'auto'`. */
  model: { id: string } | undefined;
}

export interface DecideDeps {
  checker: PolicyChecker;
  apiKey: string;
  entrypoint: string;
}

/** What pi reads back from a `tool_call` handler; Phase 8 only ever blocks or says nothing. */
export interface BlockResult {
  block: true;
  reason: string;
}

export async function decideToolCall(
  event: ToolCallLike,
  ctx: DecideCtx,
  deps: DecideDeps,
): Promise<BlockResult | undefined> {
  try {
    // Both of pi's shell tools (`bash` and `powershell`) are checked on their `command` — see
    // `narrow.ts`. Anything else carries no command and is judged server-side on `metadata`.
    const shell = isShellCall(event);
    const command = shell ? event.input.command : "";

    // Nothing to evaluate: the server's entry gate would answer allow after a full round trip, and
    // pi awaits every call in a batch serially, so each pointless trip is felt N× (§B3 / §F2).
    if (shell && command.trim() === "") return undefined;

    const payload = buildPretoolPayload({
      toolName: event.toolName,
      command,
      toolUseId: event.toolCallId,
      toolInput: (event.input ?? {}) as Record<string, unknown>,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
    });

    const outcome = await deps.checker.checkTool(payload, event.toolName);

    switch (outcome.kind) {
      case "allow":
        return undefined;

      case "deny": {
        const reason = outcome.reason;
        notifySafe(ctx, reason ?? GENERIC_DENY_REASON, "error");
        return {
          block: true,
          reason: reason === undefined ? GENERIC_DENY_REASON : DENY_PREFIX + reason,
        };
      }

      case "confirm": {
        if (!ctx.hasUI) return { block: true, reason: NO_UI_REASON };
        const reason = outcome.reason ?? GENERIC_DENY_REASON;
        // Notified as well as asked, so the reason stays in the transcript after the dialog closes.
        notifySafe(ctx, reason, "warning");
        const accepted = await confirmWithTimeout(
          ctx,
          CONFIRM_TITLE,
          reason + CONFIRM_QUESTION_SUFFIX,
        );
        return accepted ? undefined : { block: true, reason: DECLINED_REASON };
      }

      case "unavailable":
        return { block: true, reason: ENGINE_UNAVAILABLE_REASON };
    }
  } catch {
    // Belt and braces: `index.ts` catches too, but an internal fault must allow, never block.
    return undefined;
  }
}
