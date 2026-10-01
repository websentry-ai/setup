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
  CONFIRM_QUESTION,
  CONFIRM_TITLE,
  DECLINED_REASON,
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  GENERIC_DENY_REASON,
  MAX_PROMPT_CHARS,
  NO_UI_REASON,
} from "../../core/src/constants.ts";
import { areToolsFresh, shouldSkipFileToolFromState } from "../../core/src/cache.ts";
import {
  NATIVE_FILE_TOOLS,
  auditToolInput,
  buildPretoolPayload,
  capCommand,
  capMcpArgs,
  resolveFilePath,
} from "../../core/src/payload.ts";
import type { CheckHooks, PolicyChecker } from "../../core/src/policy.ts";
import type { McpCallInfo } from "../../core/src/types.ts";
import type { PolicyOutcome } from "../../core/src/verdict.ts";
import { policyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
import { isShellCall } from "./narrow.ts";
import type { ToolCallLike } from "./narrow.ts";
import { confirmWithTimeout, notifySafe } from "./ui.ts";
import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import type { UiCtx } from "./ui.ts";

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
  /**
   * The turn's user prompt, read lazily for the pretool body's `messages[0].content`.
   *
   * The gateway writes its block/warn row from the pretool `messages` (`queueHookLog`'s
   * `hookRequestBody`), so a blank there is the "empty block log" bug: a row that says a command was
   * blocked without saying what the developer had asked for. `user_prompts` is deliberately NOT sent —
   * the gateway's only reader of it falls back to `messages` anyway.
   *
   * A closure rather than a value so a call that takes an early return (nothing evaluable, cache
   * skip) costs nothing, and read through `promptOf`, so a getter that throws costs the prompt column
   * and never the verdict. Optional: absent means `""`, today's behaviour.
   */
  currentPrompt?: () => string | undefined;
  /**
   * Resolve a pi-mcp-adapter call to the MCP (server, original tool, args) it will run — see
   * `mcpResolve.ts`. Consulted only for a call that is neither a shell call nor a native file tool,
   * BEFORE the nothing-evaluable return, and only through `mcpOf`: a resolver that throws is a miss,
   * and a miss is today's path (an unevaluable custom tool: no request, allowed). Optional, so every
   * existing call site keeps that behaviour.
   */
  resolveMcp?: (toolName: string, input: unknown, cwd: string) => McpCallInfo | undefined;
}

/** `deps.resolveMcp`, made total. Anything that is not a well-formed hit is a miss. */
function mcpOf(
  deps: Pick<DecideDeps, "resolveMcp">,
  toolName: string,
  input: unknown,
  cwd: string,
): McpCallInfo | undefined {
  try {
    const call = deps.resolveMcp?.(toolName, input, cwd);
    if (call === null || typeof call !== "object") return undefined;
    if (typeof call.server !== "string" || call.server === "") return undefined;
    if (typeof call.tool !== "string" || call.tool === "") return undefined;
    if (call.args === null || typeof call.args !== "object" || Array.isArray(call.args)) return undefined;
    return call;
  } catch {
    return undefined;
  }
}

/**
 * The record's copy of the MCP arguments: the capped projection the pretool request sent, cloned so
 * the turn record never aliases pi's live `event.input` (a direct tool's input IS its arguments).
 * The clone is JSON because `capMcpArgs`' output has just been proven JSON-serialisable.
 */
function auditMcpArgs(args: Record<string, unknown>): Record<string, unknown> {
  try {
    const cloned = JSON.parse(JSON.stringify(capMcpArgs(args))) as unknown;
    return cloned !== null && typeof cloned === "object" && !Array.isArray(cloned)
      ? (cloned as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

/**
 * The prompt for the pretool `messages`, capped exactly as the prompt check caps it, or `""`.
 * Total: a throwing or non-string getter is an empty prompt, never a thrown `tool_call` (= a BLOCK).
 */
function promptOf(deps: Pick<DecideDeps, "currentPrompt">): string {
  try {
    const prompt = deps.currentPrompt?.();
    if (typeof prompt !== "string" || prompt === "") return "";
    return capCommand(prompt, MAX_PROMPT_CHARS).command;
  } catch {
    return "";
  }
}

/**
 * What the decision seam hands the turn record. Structurally a `TurnToolCall` minus `ts`, but
 * declared here rather than imported so `decide.ts` keeps no dependency on the store it feeds.
 */
export interface DecisionEntry {
  tool_name: string;
  tool_use_id: string;
  decision: string;
  /** Already allowlisted and capped by `auditToolInput`. Absent is allowed; raw input is not. */
  tool_input?: Record<string, unknown>;
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
export function noteDecision(deps: Pick<DecideDeps, "onDecision">, entry: DecisionEntry): void {
  noteSafe(() => deps.onDecision?.(entry));
}

/**
 * The guard itself, for any audit emission that is not a decision entry (WR-06).
 *
 * `prompt.ts` used to call `deps.onPrompt?.(text)` bare, inside its own fail-open try/catch, which
 * restated the invariant by omission instead of reusing it. Benign only by coincidence — both of that
 * function's call sites already returned `undefined`, so a throw landed on the same answer. It stops
 * being benign the moment anyone records the prompt before the deny branch, moves the call, or adds a
 * verdict between them, and the failure would be a silently UN-suppressed prompt with no test
 * pointing at it, because at that call site the hazard is invisible.
 *
 * One wrapper, exported, so the rule has a single place to be true.
 */
export function noteSafe(fn: (() => void) | undefined): void {
  try {
    fn?.();
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

    // A pi-mcp-adapter call (proxy, namespace wrapper or direct tool) goes to the gateway's MCP path
    // instead, resolved forward to (server, original tool, args). Asked only of a call that is
    // neither a shell call nor a native file tool, so the common path costs nothing.
    if (!shell && !NATIVE_FILE_TOOLS.has(event.toolName)) {
      const mcp = mcpOf(deps, event.toolName, event.input, ctx.cwd);
      if (mcp !== undefined) return await decideMcpCall(event, ctx, deps, mcp);
    }

    // Nothing to evaluate: the server's entry gate needs a non-blank command or a native-tool
    // `file_path` (§B3), so a call with neither is a guaranteed allow after a full round trip — and
    // pi awaits every call in a batch serially, so each pointless trip is felt N× (§F2). This covers
    // every custom tool that carries no command, including an MCP-looking call the resolver could
    // not attribute to exactly one (server, tool) — not just an empty shell command (WR-04).
    const filePath = resolveFilePath(event.toolName, toolInput, ctx.cwd);
    if (command.trim() === "" && filePath === undefined) return undefined;

    // The audit projection, computed once for whichever branch below records the decision. Derived
    // from the same `toolInput` and the same functions `buildPretoolPayload` uses, so the two agree by
    // construction rather than by a comment — and computed here, because this is the last scope that
    // has the live input at all.
    const auditInput = auditToolInput(toolInput, command);

    const now = (deps.now ?? Date.now)();
    const state = deps.state ?? policyState;

    // WR-02. "The server has already told us" is the entire justification for the skip below, so the
    // skip is gated on the server having told *this process* — not on a number a file supplied.
    // `policyState.hydrate` never sets this bit, so it is false until the first response that carries
    // `tools_to_check` lands, which the forced pull below guarantees happens on the first real tool
    // call of the session.
    //
    // Without it, a same-UID local process could read `policy_cache.json` — which hands it both
    // halves of the identity in cleartext — rewrite it as `{tools_to_check: [], tools_synced_at: now}`
    // and disable every read/write/edit/grep/find/ls for 300 s, renewably, while enforcement reported
    // itself active. Cost of the fix is one round trip per session; the warm cache still pays for
    // itself on every call after the first.
    const toolsConfirmed = state.getToolsConfirmed();

    // RES-03's fast path. When the org's own tool list is tools-FRESH and does not name this tool,
    // the server has already told us there is no file policy that could apply — so there is nothing
    // to ask, and no payload is even built. Bounded to the six native file tools: a shell command or
    // a custom tool is evaluated on its `command`, which no cached list can answer for.
    if (
      toolsConfirmed &&
      NATIVE_FILE_TOOLS.has(event.toolName) &&
      shouldSkipFileToolFromState(event.toolName, state, now)
    ) {
      // Recorded, not silent: "we did not ask" is a different audit fact from "we asked and it was
      // allowed", and a turn log that showed them identically would make the cache invisible.
      noteDecision(deps, {
        tool_name: event.toolName,
        tool_use_id: event.toolCallId,
        decision: "skipped",
        // Recorded on this path too: a skip is still a call the developer made, and the path it was
        // made against is what makes the row readable.
        tool_input: auditInput,
      });
      return undefined;
    }

    // `tools_to_check` arrives on the command-policy path ONLY (§C2), so a genuine tool call is the
    // only thing that can fill the cache. Ask for it when the list is missing or stale — never by
    // fabricating a request: a synthetic `ls` would be evaluated as a real tool use and can fire a
    // Slack approval for a command nobody ran.
    //
    // An UNCONFIRMED list is always pulled, however fresh its stamp looks (WR-02). That is the
    // self-heal: the first real tool call of the session round-trips, the response re-establishes the
    // list from the server, `toolsConfirmed` flips, and every call after this one takes the TTL logic
    // exactly as before.
    const pullPolicies = !toolsConfirmed || !areToolsFresh(state.getToolsSyncedAt(), now);

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
      // Read here, after both early returns: a skipped call never pays for it.
      lastUserPrompt: promptOf(deps),
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
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
      tool_input: auditInput,
    });

    return await applyOutcome(outcome, ctx);
  } catch {
    // Belt and braces: `index.ts` catches too, but an internal fault must allow, never block.
    return undefined;
  }
}

/**
 * A resolved MCP call: the gateway's Path 3, never the file-tool cache.
 *
 * The 300 s skip answers "is there a FILE policy for this tool" from a cached list, and no cached list
 * can say whether an MCP sanction or MCP policy applies — so an MCP call always round-trips. It still
 * pulls policies on the same rule as every other call, because the MCP response carries
 * `tools_to_check` when asked. The checker's label stays pi's own tool name; the body and the turn
 * record both name the call `mcp__<server>__<tool>`, which is what the gateway and the backend parse.
 */
async function decideMcpCall(
  event: ToolCallLike,
  ctx: DecideCtx,
  deps: DecideDeps,
  mcp: McpCallInfo,
): Promise<BlockResult | undefined> {
  const now = (deps.now ?? Date.now)();
  const state = deps.state ?? policyState;
  const pullPolicies = !state.getToolsConfirmed() || !areToolsFresh(state.getToolsSyncedAt(), now);

  const payload = buildPretoolPayload({
    toolName: event.toolName,
    command: "",
    toolUseId: event.toolCallId,
    toolInput: {},
    cwd: ctx.cwd,
    sessionId: ctx.sessionManager.getSessionId(),
    model: ctx.model?.id,
    clientEntrypoint: deps.entrypoint,
    pullPolicies,
    lastUserPrompt: promptOf(deps),
    mcp,
    ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
  });

  const hooks: CheckHooks =
    deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
  const outcome = await deps.checker.checkTool(payload, event.toolName, hooks);
  // Before the confirm, for the same reason as the native path. The capped arguments are what the
  // record carries — the same projection the gateway saw — and `turnLog.ts` redacts every string
  // leaf of them before they are posted.
  noteDecision(deps, {
    tool_name: `mcp__${mcp.server}__${mcp.tool}`,
    tool_use_id: event.toolCallId,
    decision: outcome.kind,
    tool_input: auditMcpArgs(mcp.args),
  });
  return await applyOutcome(outcome, ctx);
}

/** The verdict-to-pi-behaviour mapping both paths share — header rules 1 and 2 live here. */
async function applyOutcome(outcome: PolicyOutcome, ctx: DecideCtx): Promise<BlockResult | undefined> {
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
      // rejected key at a fail-closed org). It is a constant, never API text.
      return { block: true, reason: outcome.reason ?? ENGINE_UNAVAILABLE_REASON };
  }
  return undefined;
}
