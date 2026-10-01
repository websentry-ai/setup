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
// Every user-facing string comes from a `constants.ts` (core's, or this package's for pi-only
// wording) or from core's `verdictMessage`; none is retyped here.
//
// The decision itself — what is skipped, what is sent, what the policy answered — is made by core's
// evaluation API, shared with every other adapter. This file computes pi's shell command for the
// call and maps the verdict onto pi's `{block, reason}` result, its notices and its confirm dialog.

import {
  CONFIRM_QUESTION,
  CONFIRM_TITLE,
  DECLINED_REASON,
  GENERIC_DENY_REASON,
} from "../../core/src/constants.ts";
import { evaluateToolCall, verdictMessage } from "../../core/src/evaluate.ts";
import type { DecisionEntry } from "../../core/src/evaluate.ts";
import type { CheckHooks, PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
import { isShellCall } from "./narrow.ts";
import type { ToolCallLike } from "./narrow.ts";
import { NO_UI_REASON } from "./constants.ts";
import { PI_PROFILE } from "./profile.ts";
import { confirmWithTimeout, notifySafe } from "./ui.ts";
import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import type { UiCtx } from "./ui.ts";

// The decision seam's entry type and its two guards live in core (`evaluate.ts`), next to the code
// that emits the entries. Re-exported here because `userBash.ts`, `prompt.ts` and the tests reach
// them through this module.
export { noteDecision, noteSafe } from "../../core/src/evaluate.ts";
export type { DecisionEntry } from "../../core/src/evaluate.ts";

/** The structural slice of `ExtensionContext` a decision needs (§A4). */
export interface DecideCtx extends UiCtx {
  cwd: string;
  sessionManager: { getSessionId(): string };
  /**
   * `Model | undefined` in pi — the payload builder substitutes `'auto'`. `provider` is read only by
   * the account-identity lookup at `session_start`, to pick the matching `auth.json` entry.
   */
  model: { id: string; provider?: string } | undefined;
}

export interface DecideDeps {
  checker: PolicyChecker;
  apiKey: string;
  entrypoint: string;
  /** Injectable clock, so a 300 s cache-TTL test runs in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * The remembered policy metadata. Defaults to the process-wide `policyState`, which is the right
   * production answer — the memory has to survive across tool calls within a session.
   *
   * Injectable because the singleton only ever moves forward: once a response has taught it a
   * `tools_to_check`, no test in the same process can get back to "nothing learned", and the
   * cache-skip cases are precisely about that starting point.
   */
  state?: PolicyState;
  /**
   * The per-call notice channel handed to `checkTool`. Defaults to a closure over the live `ctx`,
   * which is what makes 09-02's breaker-open and key-rejected notices reachable at all: the checker
   * is built once in `init()` and can never capture a `ctx` of its own.
   */
  hooks?: CheckHooks;
  /**
   * Hand the decision that actually applied to the turn record (RES-04).
   *
   * Without this seam the `PolicyOutcome.kind` dies inside this function — `decideToolCall` returns
   * `BlockResult | undefined`, which cannot distinguish an allow from a cache skip from a declined
   * confirm. The turn log's `tool_calls[].decision` has no other source.
   *
   * Optional so 09-03's call sites compile untouched, and **called through `noteDecision`**, never
   * directly: an audit record must not be able to change a verdict.
   *
   * `tool_input` rides the same seam for the same reason: this function is the last place the live
   * `event.input` is in scope, so it is the only place that can hand the record the allowlisted
   * projection of it. What travels is `auditToolInput`'s output, never `event.input` itself.
   */
  onDecision?: (entry: DecisionEntry) => void;
  /**
   * The process's settled account identity, attached to the pretool body as `account_identity`.
   * Never awaited here: a tool call does not wait on a profile lookup, so a call made before the
   * lookup settles simply goes without it (the Python hook's pre-tool path reads a cache, likewise).
   */
  accountIdentity?: AccountIdentity;
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

    // Everything agent-independent happens in core: the nothing-to-evaluate skip, the cached
    // file-tool skip (recorded as "skipped"), the payload, the check and the decision entry. Core's
    // function is total, so the only outcomes here are a verdict or a skip.
    const verdict = await evaluateToolCall(
      {
        toolName: event.toolName,
        toolCallId: event.toolCallId,
        command,
        // `null` and `undefined` inputs both become `{}` here — see `narrow.ts` on why `input` is
        // `unknown` and can genuinely be either (WR-07).
        toolInput: (event.input ?? {}) as Record<string, unknown>,
        cwd: ctx.cwd,
        // Getters, so the live session is read only when a payload is actually built — a skipped
        // call never touches it, exactly as before this path moved into core. A read that fails
        // there is core's fault path: the call is allowed.
        get sessionId(): string {
          return ctx.sessionManager.getSessionId();
        },
        get model(): string | undefined {
          return ctx.model?.id;
        },
      },
      {
        checker: deps.checker,
        profile: PI_PROFILE,
        entrypoint: deps.entrypoint,
        // pi has one key and one gateway per process, so its policy memory is the process-wide
        // singleton. Core requires the state explicitly (it has no default of its own), so pi's
        // wiring names it here; a test may still inject a fresh one.
        state: deps.state ?? policyState,
        now: deps.now,
        // `notifySafe` already swallows its own failures, and core wraps the call again: a notice
        // must never be able to change a verdict.
        hooks: deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) },
        onDecision: deps.onDecision,
        accountIdentity: deps.accountIdentity,
      },
    );

    switch (verdict.kind) {
      case "skip":
      case "allow":
        return undefined;

      case "deny": {
        notifySafe(ctx, verdict.reason ?? GENERIC_DENY_REASON, "error");
        // `DENY_PREFIX + reason`, or the generic text when the API gave no reason.
        return { block: true, reason: verdictMessage(verdict) };
      }

      case "confirm": {
        if (!ctx.hasUI) return { block: true, reason: NO_UI_REASON };
        const reason = verdict.reason ?? GENERIC_DENY_REASON;
        // The notice is where the reason is rendered — once. It also stays in the transcript after the
        // dialog closes, which is why it is the copy that was kept when the dialog stopped repeating
        // it: pi draws a confirm as `title\nmessage`, so a reason in both places was the same
        // paragraph twice on one verdict.
        notifySafe(ctx, reason, "warning");
        const accepted = await confirmWithTimeout(ctx, CONFIRM_TITLE, CONFIRM_QUESTION);
        return accepted ? undefined : { block: true, reason: DECLINED_REASON };
      }

      case "unavailable":
        // Core supplies a `reason` only when the generic string would misdescribe the failure (a
        // rejected key at a fail-closed org). It is a constant, never API text. Without one this is
        // `ENGINE_UNAVAILABLE_REASON`.
        return { block: true, reason: verdictMessage(verdict) };
    }
  } catch {
    // Belt and braces: `index.ts` catches too, but an internal fault must allow, never block.
    return undefined;
  }
}
