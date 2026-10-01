// HOOK-04 — the `user_bash` adapter. A developer typing `!cmd` (or `!!cmd`) in pi gets exactly the
// same policy decision a model-issued `bash` tool call gets.
//
// Three things make this event different from `tool_call`, and all three shape the code below.
//
//   1. **pi fails CLOSED and SILENTLY here.** `emitUserBash` rethrows a handler error
//      (`runner.js:868-893`), `interactive-mode.js:5656-5666` then returns *without* falling back to
//      local execution, and `rpc-mode.js:442` has no try/catch at all. A fault in this file therefore
//      does not fail open and does not even produce an error the user can act on — the command simply
//      never runs. So the whole body sits inside one try/catch whose fallback is `undefined`, which
//      means "no opinion, run it yourself".
//   2. **The result is not a `{block, reason}`.** It is pi's own `BashResult`, built only by
//      `denyBashResult` (see `bashResult.ts` for the runtime validator it satisfies). pi renders the
//      output under the command and hands it to `recordBashResult`, so the reason is shown AND enters
//      the model's context — unless `!!` was typed, which excludes it from context but still shows
//      it. That is why the deny branch also notifies: the notice is the channel that survives `!!`.
//   3. **The event has no id, and carries its own cwd.** `UserBashEvent` is
//      `{type, command, excludeFromContext, cwd}` — no `toolCallId` — so the `tool_use_id` is
//      generated here, and `metadata.cwd` must come from the EVENT. `ctx.cwd` is the session's
//      directory and can differ from where the command will actually run.
//
// `excludeFromContext` is read by nobody in this file on purpose: it is an input signal describing
// how pi will handle the output, not something a handler sets.

import { randomBytes } from "node:crypto";

import type { UserBashEvent, UserBashEventResult } from "@earendil-works/pi-coding-agent";

import {
  CONFIRM_QUESTION,
  CONFIRM_TITLE,
  DECLINED_REASON,
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  GENERIC_DENY_REASON,
  NO_UI_REASON,
  USER_BASH_ID_PREFIX,
} from "../../core/src/constants.ts";
import { auditToolInput, buildPretoolPayload } from "../../core/src/payload.ts";
import type { CheckHooks } from "../../core/src/policy.ts";
import { denyBashResult } from "./bashResult.ts";
import { noteDecision } from "./decide.ts";
import type { DecideCtx, DecideDeps } from "./decide.ts";
import { PI_PROFILE } from "./profile.ts";
import { confirmWithTimeout, notifySafe } from "./ui.ts";

/** The structural slice of `UserBashEvent` this adapter reads. */
export interface UserBashLike {
  command: string;
  cwd: string;
}

/**
 * Drift alarm, the same device `narrow.ts` uses for `ToolCallEvent`: pi's real event must stay
 * assignable to the slice above. A renamed `cwd` resolves this to `never` and fails `npm run
 * typecheck` instead of silently sending the wrong directory.
 */
export type UserBashEventIsCompatible = UserBashEvent extends UserBashLike ? true : never;

/**
 * pi gives the event no id, so one is minted per invocation: 10 random bytes as 20 hex characters
 * behind `ubash_`. It has to be unique per command — a shared id would make the gateway treat two
 * unrelated commands as one call, which matters for approval dedupe and for the audit trail.
 */
function newUserBashId(): string {
  return USER_BASH_ID_PREFIX + randomBytes(10).toString("hex");
}

export async function decideUserBash(
  event: UserBashLike,
  // `cwd` on this type is deliberately unused here — see the header. The rest of the slice (UI,
  // session id, model) is identical to what a tool-call decision needs, so the type is shared.
  ctx: DecideCtx,
  deps: DecideDeps,
): Promise<UserBashEventResult | undefined> {
  try {
    const command = typeof event.command === "string" ? event.command : "";
    // Nothing to evaluate. The server's entry gate would answer `allow` after a full round trip.
    if (command.trim() === "") return undefined;

    // Hoisted out of the payload build so the turn record can reference the same id the gateway saw:
    // a `tool_calls[]` entry whose `tool_use_id` did not match the audited call would be unjoinable.
    const toolUseId = newUserBashId();
    const payload = buildPretoolPayload({
      // A user-typed command IS a bash command; Phase 7 registered the lowercase name.
      toolName: "bash",
      command,
      toolUseId,
      // Empty by construction: there is no model-produced input here, so the allowlist has nothing
      // to forward and no file body can ride along.
      toolInput: {},
      cwd: event.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
    }, PI_PROFILE);

    const hooks: CheckHooks =
      deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, "bash", hooks);
    // A typed `!cmd` is a real tool call in the audit trail, so it belongs in the turn record on the
    // same terms — `noteDecision` swallows its own failures, which matters more here than anywhere:
    // a throw out of this function means the command silently never runs (§A1.2).
    noteDecision(deps, {
      tool_name: "bash",
      tool_use_id: toolUseId,
      decision: outcome.kind,
      // `{}` in, so the only key out is the capped `command` — which is the entire content of a
      // `!cmd`, and what the audit row would otherwise have described as an unnamed bash call.
      tool_input: auditToolInput({}, command),
    });

    switch (outcome.kind) {
      case "allow":
        return undefined;

      case "deny": {
        const reason = outcome.reason;
        notifySafe(ctx, reason ?? GENERIC_DENY_REASON, "error");
        return denyBashResult(reason === undefined ? GENERIC_DENY_REASON : DENY_PREFIX + reason);
      }

      case "confirm": {
        if (!ctx.hasUI) return denyBashResult(NO_UI_REASON);
        const reason = outcome.reason ?? GENERIC_DENY_REASON;
        // See `decide.ts`: the notice carries the reason, the dialog asks the question. On this path
        // the notice matters more still — it is what survives `!!`, which keeps the rendered output
        // out of the model's context.
        notifySafe(ctx, reason, "warning");
        const accepted = await confirmWithTimeout(ctx, CONFIRM_TITLE, CONFIRM_QUESTION);
        return accepted ? undefined : denyBashResult(DECLINED_REASON);
      }

      case "unavailable":
        // See `decide.ts`: a core constant when the generic string would be wrong, never API text.
        return denyBashResult(outcome.reason ?? ENGINE_UNAVAILABLE_REASON);

      default:
        // An outcome kind nothing here maps — a future core enum value, or a bug. Returning a
        // half-built object would fail pi's validator, which is a silent block; `undefined` is the
        // only safe answer to "I do not know".
        return undefined;
    }
  } catch {
    // The whole point of this file. Never a throw, never `{operations}`, never a partial result.
    return undefined;
  }
}
