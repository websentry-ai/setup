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
import { areToolsFresh, shouldSkipFileToolFromState } from "../../core/src/cache.ts";
import { NATIVE_FILE_TOOLS, buildPretoolPayload, resolveFilePath } from "../../core/src/payload.ts";
import type { CheckHooks, PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
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
   */
  onDecision?: (entry: { tool_name: string; tool_use_id: string; decision: string }) => void;
}

/**
 * Emit one `onDecision` entry, swallowing everything.
 *
 * The guard is load-bearing, not defensive noise. `deps.onDecision` is wired to the module-scope turn
 * store via a closure that reads `ctx.sessionManager.getSessionId()`; a throw from any of that inside
 * the `try` below would be caught by the fail-open `catch` and return `undefined` — i.e. **allow** —
 * even when the outcome was a deny. Shared with `userBash.ts`, which has the same hazard and a worse
 * failure mode.
 */
export function noteDecision(
  deps: Pick<DecideDeps, "onDecision">,
  entry: { tool_name: string; tool_use_id: string; decision: string },
): void {
  try {
    deps.onDecision?.(entry);
  } catch {
    // An audit line is never worth a verdict.
  }
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
    // Computed once and handed to both the skip decision and the payload, so the two cannot disagree
    // about what this call carries. `null` and `undefined` inputs both become `{}` here — see
    // `narrow.ts` on why `input` is `unknown` and can genuinely be either (WR-07).
    const toolInput = (event.input ?? {}) as Record<string, unknown>;

    // Nothing to evaluate: the server's entry gate needs a non-blank command or a native-tool
    // `file_path` (§B3), so a call with neither is a guaranteed allow after a full round trip — and
    // pi awaits every call in a batch serially, so each pointless trip is felt N× (§F2). This covers
    // every custom/MCP tool that carries no command, not just an empty shell command (WR-04).
    const filePath = resolveFilePath(event.toolName, toolInput, ctx.cwd);
    if (command.trim() === "" && filePath === undefined) return undefined;

    const now = (deps.now ?? Date.now)();
    const state = deps.state ?? policyState;

    // RES-03's fast path. When the org's own tool list is tools-FRESH and does not name this tool,
    // the server has already told us there is no file policy that could apply — so there is nothing
    // to ask, and no payload is even built. Bounded to the six native file tools: a shell command or
    // a custom tool is evaluated on its `command`, which no cached list can answer for.
    if (NATIVE_FILE_TOOLS.has(event.toolName) && shouldSkipFileToolFromState(event.toolName, state, now)) {
      // Recorded, not silent: "we did not ask" is a different audit fact from "we asked and it was
      // allowed", and a turn log that showed them identically would make the cache invisible.
      noteDecision(deps, {
        tool_name: event.toolName,
        tool_use_id: event.toolCallId,
        decision: "skipped",
      });
      return undefined;
    }

    // `tools_to_check` arrives on the command-policy path ONLY (§C2), so a genuine tool call is the
    // only thing that can fill the cache. Ask for it when the list is missing or stale — never by
    // fabricating a request: a synthetic `ls` would be evaluated as a real tool use and can fire a
    // Slack approval for a command nobody ran.
    const pullPolicies = !areToolsFresh(state.getToolsSyncedAt(), now);

    const payload = buildPretoolPayload({
      toolName: event.toolName,
      command,
      toolUseId: event.toolCallId,
      toolInput,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      pullPolicies,
    });

    // `notifySafe` already swallows its own failures, and `policy.ts` wraps the call again: a notice
    // must never be able to change a verdict.
    const hooks: CheckHooks =
      deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    const outcome = await deps.checker.checkTool(payload, event.toolName, hooks);
    // Immediately, before the confirm dialog: the decision is what the POLICY said, and a turn log
    // that waited for a 120 s modal would be recording the developer's answer instead.
    noteDecision(deps, {
      tool_name: event.toolName,
      tool_use_id: event.toolCallId,
      decision: outcome.kind,
    });

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
