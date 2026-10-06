// The adapter-facing evaluation API: one tool call or one prompt in, one verdict out.
//
// THE CONTRACT, for every adapter:
//
//   1. `evaluateToolCall`, `evaluatePrompt` and `verdictMessage` never throw, and the two promises
//      never reject — for any input: null, wrong types, getters that throw, a checker, a notice
//      hook, an audit sink or a profile function that throws.
//   2. An error is never turned into a deny, a confirm or an unavailable. A fault inside this file
//      resolves to `allow`. The only non-allow verdicts are the ones the policy checker returned,
//      plus `unavailable` when the checker did not answer in time AND the org's last-known
//      `policy_check_failure_action` is `block`.
//   3. The promises settle within a bounded time even if the checker never does.
//
// That is what lets an adapter be total with exactly one deliberate throw site. For a host that
// blocks a tool call by throwing from its hook, the whole handler is:
//
//     const v = await evaluateToolCall(call, deps);
//     if (v.kind === "deny") throw new Error(verdictMessage(v));
//
// Whether `confirm` and `unavailable` also block is the adapter's decision, made from its own host's
// semantics (can it ask the user? does it have a UI?). `verdictMessage` gives the text for each. An
// adapter must not raise a deny from anything else: not from a caught exception, not from a
// timeout of its own.
//
// What is here is the agent-independent half of a decision, parameterised by the injected
// `AgentProfile`: the nothing-to-evaluate skip, the cached file-tool skip, the payload, the check,
// the audit entry. What is NOT here is how an agent computes the shell command for a tool call and
// how it shows a verdict to its user; those stay in the adapter package.
//
// This file has no throw statement, and a test keeps it that way.

import type { AccountIdentity } from "./accountIdentity.ts";
import { areToolsFresh, shouldSkipFileToolFromState } from "./cache.ts";
import {
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  EVALUATE_DEADLINE_ERROR_CLASS,
  EVALUATE_DEADLINE_SLACK_MS,
  GENERIC_DENY_REASON,
  PRETOOL_TIMEOUT_MS,
} from "./constants.ts";
import {
  auditToolInput,
  buildPretoolPayload,
  buildPromptPayload,
  nativeFileTools,
  normaliseMcp,
  profileExtraToolInputKeys,
  resolveFilePath,
} from "./payload.ts";
import type { CheckHooks, PolicyChecker } from "./policy.ts";
import { createPolicyState } from "./policyState.ts";
import type { PolicyState } from "./policyState.ts";
import type { AgentProfile } from "./profile.ts";
import type { Telemetry } from "./telemetry.ts";
import type { PretoolRequestBody } from "./types.ts";
import { sanitizeReason } from "./verdict.ts";
import type { PolicyOutcome } from "./verdict.ts";

/**
 * One tool call, as the adapter sees it. Every field is re-read as `unknown` inside: the values
 * come from a host and a model, so the types are claims.
 *
 * `sessionId` and `model` are read only when a payload is built, so an adapter may supply them as
 * getters over its live host context and a skipped call never touches that context.
 */
export interface ToolCallInput {
  toolName: string;
  toolCallId: string;
  /** The shell command this call runs, or `""` when it is not a shell call. The adapter decides. */
  command: string;
  toolInput: Record<string, unknown>;
  cwd: string;
  sessionId: string;
  model: string | undefined;
  /**
   * Explicit MCP attribution, when the adapter knows this call goes to an MCP server. Sent as
   * `metadata.mcp_server` / `metadata.mcp_tool`, and makes a call with no command and no file path
   * evaluable. Validated inside; an unusable value is treated as absent.
   */
  mcp?: { server: string; tool: string };
  /**
   * Send this call even when it carries no command, no file path and no usable MCP attribution.
   * For an adapter whose host can route a call to a tool server it could not attribute (an MCP
   * server added at runtime, a name over the attribution cap): the server must still see the call,
   * so it can log the attribution miss and apply whatever it can. Only `true` counts. Absent on
   * every adapter that does not set it, so their wire behaviour is unchanged.
   */
  sendUnattributed?: boolean;
  /**
   * `"delete"` for a per-file request whose target the call deletes (sent as
   * `metadata.patch_operation`). Only that exact value counts; absent on every adapter that does not
   * set it, so their wire behaviour is unchanged.
   */
  patchOperation?: "delete";
}

/** One user prompt, as the adapter sees it. Images and attachments have no field here on purpose. */
export interface PromptInput {
  text: string;
  /** `"extension"` marks text the host or another extension generated; it is not checked. */
  source?: "interactive" | "rpc" | "extension" | string;
  cwd: string;
  sessionId: string;
  model: string | undefined;
  hasUI: boolean;
}

/**
 * What the decision seam hands an adapter's turn record. Structurally a turn tool call minus its
 * timestamp, declared here so this file keeps no dependency on the store it feeds.
 */
export interface DecisionEntry {
  tool_name: string;
  tool_use_id: string;
  decision: string;
  /** Already allowlisted and capped by `auditToolInput`. Absent is allowed; raw input is not. */
  tool_input?: Record<string, unknown>;
}

export interface EvaluateDeps {
  checker: PolicyChecker;
  profile: Pick<AgentProfile, "appLabel" | "fileTools" | "extraToolInputKeys">;
  /** `client_entrypoint` on the wire: "<agent>/<version>". */
  entrypoint: string;
  /**
   * The remembered policy metadata for the org this call is checked against: the SAME instance the
   * checker records responses into. Required, with no default (WR-03). The memory is per org and
   * per gateway, so which instance is right depends on the adapter: pi (one key, one gateway per
   * process) passes the process-wide `policyState` explicitly; a host serving several projects
   * passes `createScopedStates().forScope(baseUrl, apiKey).policy`. A silent fall back to a process
   * singleton would let one project's tool list or failure action decide another's calls.
   *
   * A caller that ignores the type and passes nothing usable gets a fresh, unstored state for that
   * one call, which fails toward checking (no tool is cache-skipped), never the singleton.
   */
  state: PolicyState;
  /** Injectable clock, so a 300 s cache-TTL test runs in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  /** The per-call notice channel handed to the checker. Its failures are swallowed here. */
  hooks?: CheckHooks;
  /**
   * Receives the decision that applied, for the adapter's turn record: the checker's outcome kind,
   * or `"skipped"` for a cached skip. Called through `noteDecision`, so a failing sink cannot change
   * a verdict.
   */
  onDecision?: (entry: DecisionEntry) => void;
  /** The process's settled account identity, when known. Never awaited on this path. */
  accountIdentity?: AccountIdentity;
  /**
   * Upper bound on how long one evaluation waits for the checker. Defaults to
   * `PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS`; anything that is not a positive finite number
   * falls back to that default.
   */
  deadlineMs?: number;
  /**
   * Where an outer-deadline timeout is reported (IN-02): `reportBypass` with
   * `errorClass: EVALUATE_DEADLINE_ERROR_CLASS`, the label the checker was given as `toolName`, the
   * deadline as `elapsedMs`, and `blocked` when the timeout became `unavailable`. So a fail-closed
   * block the user saw, or a fail-open timeout, leaves the same trace a client failure does.
   * Optional: without it a timeout is still audited through `onDecision`, just not reported. Called
   * through `noteSafe`, so a failing reporter cannot change the verdict.
   */
  telemetry?: Pick<Telemetry, "reportBypass">;
}

/** A policy outcome, or a call that was never sent for a check. */
export type ToolEvaluation = PolicyOutcome | { kind: "skip"; why: "nothing-evaluable" | "cached" };

/** The `source` value that marks a prompt as host-generated rather than typed by a user. */
const HOST_GENERATED_SOURCE = "extension";
/** `setTimeout` treats a larger delay as 1 ms. */
const MAX_TIMER_MS = 2_147_483_647;

// Run an audit emission and swallow whatever it does.
//
// The guard is load-bearing. A sink is typically a closure over an adapter's turn store and its live
// host context; an exception from it inside a decision's try block would be caught by the fail-open
// catch and answered as an allow, even when the outcome was a deny. One wrapper, exported, so that
// rule has a single place to be true. Adapters use it for any audit emission of their own.
export function noteSafe(fn: (() => void) | undefined): void {
  try {
    fn?.();
  } catch {
    // An audit line is never worth a verdict.
  }
}

/** Emit one `onDecision` entry through `noteSafe`. */
export function noteDecision(deps: Pick<EvaluateDeps, "onDecision">, entry: DecisionEntry): void {
  noteSafe(() => deps.onDecision?.(entry));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// The caller's state, or a fresh one for this call only. Never a process singleton (WR-03): a fresh
// state has no confirmed tool list and no remembered failure action, so nothing is skipped and a
// timeout allows, which is the cold-start behaviour.
function resolveState(raw: unknown): PolicyState {
  return raw !== null && typeof raw === "object" ? (raw as PolicyState) : createPolicyState();
}

function resolveDeadlineMs(raw: unknown): number {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return Math.min(raw, MAX_TIMER_MS);
  return PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS;
}

/** A notice channel whose every emission is swallowed, so a checker may call it unguarded. */
function safeHooks(hooks: CheckHooks | undefined): CheckHooks | undefined {
  if (hooks === undefined || hooks === null) return undefined;
  return {
    notify(message, level) {
      noteSafe(() => hooks.notify?.(message, level));
    },
  };
}

type Raced =
  | { state: "answered"; value: unknown }
  // The checker raised or rejected.
  | { state: "faulted" }
  | { state: "timed-out" };

// Start `start()` and wait for it for at most `deadlineMs`. The returned promise always resolves.
//
// The timer is cleared as soon as the work settles, so on the normal path it never extends a
// process's lifetime and never fires late into a finished call. A result that arrives after the
// deadline is dropped.
//
// The timer is deliberately NOT unref'd (WR-01). It only outlives the work when the work hangs, and
// then it IS the guarantee: a checker stuck on a lost resolver holds no handle of its own, so an
// unref'd deadline would let Node exit 0 mid tool call with no verdict, and a fail-closed org would
// never get its `unavailable`. Keeping the process alive for at most `deadlineMs` while a check is
// outstanding is exactly what contract item 3 promises.
function raceDeadline(start: () => unknown, deadlineMs: number): Promise<Raced> {
  return new Promise<Raced>((resolve) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: Raced): void => {
      if (done) return;
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(result);
    };
    try {
      timer = setTimeout(() => finish({ state: "timed-out" }), deadlineMs);
      Promise.resolve(start()).then(
        (value) => finish({ state: "answered", value }),
        () => finish({ state: "faulted" }),
      );
    } catch {
      finish({ state: "faulted" });
    }
  });
}

// Rebuild the checker's answer as one of the four outcomes, from scratch.
//
// Anything that is not a recognised kind is an allow: a block is the result a malformed answer must
// never produce. A `reason` survives only as a string. The object returned is new, so nothing the
// checker keeps a reference to can change a verdict after it was returned.
function normaliseOutcome(raw: unknown): PolicyOutcome {
  if (raw === null || typeof raw !== "object") return { kind: "allow" };
  const kind = (raw as { kind?: unknown }).kind;
  if (kind !== "deny" && kind !== "confirm" && kind !== "unavailable") return { kind: "allow" };
  const reason = (raw as { reason?: unknown }).reason;
  return typeof reason === "string" ? { kind, reason } : { kind };
}

// Ask the checker, bounded by the deadline. `undefined` means the checker raised or rejected: the
// caller allows and records nothing, since no decision was made.
//
// On a timeout the org's failure action decides, the same rule `policy.ts` applies to a failed
// request: allow, unless the last-known `policy_check_failure_action` is `block`. With nothing
// remembered (a cold start) that is an allow.
async function check(
  payload: PretoolRequestBody,
  label: string,
  deps: EvaluateDeps,
  state: PolicyState,
): Promise<PolicyOutcome | undefined> {
  const hooks = safeHooks(deps.hooks);
  const deadlineMs = resolveDeadlineMs(deps.deadlineMs);
  const raced = await raceDeadline(() => deps.checker.checkTool(payload, label, hooks), deadlineMs);
  if (raced.state === "answered") return normaliseOutcome(raced.value);
  if (raced.state === "faulted") return undefined;
  const blocked = state.getFailureAction() === "block";
  // IN-02: the timeout is an enforcement failure like any other, so it is reported the way
  // `policy.ts` reports a failed request — after the failure action is decided, so a fail-closed
  // block is filed as a block and not as a bypass.
  noteSafe(() =>
    deps.telemetry?.reportBypass({
      errorClass: EVALUATE_DEADLINE_ERROR_CLASS,
      toolName: label,
      elapsedMs: deadlineMs,
      blocked,
    }),
  );
  return blocked ? { kind: "unavailable" } : { kind: "allow" };
}

/**
 * Evaluate one tool call. Total: resolves for any input, and resolves to `allow` on any fault.
 *
 * `skip` means no request was made: either the call carries nothing the server evaluates, or the
 * org's own tool list (server-confirmed and fresh) says no file policy applies to this tool.
 */
export async function evaluateToolCall(call: ToolCallInput, deps: EvaluateDeps): Promise<ToolEvaluation> {
  try {
    const source: Partial<Record<keyof ToolCallInput, unknown>> = isRecord(call) ? call : {};
    const toolName = asString(source.toolName);
    const toolCallId = asString(source.toolCallId);
    const command = asString(source.command);
    // Computed once and handed to both the skip decision and the payload, so the two cannot disagree
    // about what this call carries. Anything that is not a plain object becomes `{}`.
    const toolInput = isRecord(source.toolInput) ? source.toolInput : {};
    const cwd = asString(source.cwd);
    const profile = deps.profile;

    // Explicit MCP attribution, validated once here and handed to the payload as the validated value.
    const mcp = normaliseMcp(source.mcp);

    // Nothing to evaluate: the server's entry gate needs a non-blank command, a native-tool
    // `file_path`, or an explicitly attributed MCP server, so a call with none of them is a
    // guaranteed allow after a full round trip. This covers every custom tool that carries no
    // command, not just an empty shell command (WR-04). An adapter that asks for an unattributed
    // tool-server call to be sent anyway (`sendUnattributed`) bypasses this gate only.
    const filePath = resolveFilePath(toolName, toolInput, cwd, profile.fileTools);
    const sendUnattributed = source.sendUnattributed === true;
    if (!sendUnattributed && command.trim() === "" && filePath === undefined && mcp === undefined) {
      return { kind: "skip", why: "nothing-evaluable" };
    }

    // The audit projection, computed once for whichever branch below records the decision. Derived
    // from the same `toolInput`, the same extra keys and the same functions `buildPretoolPayload`
    // uses, so the two agree by construction.
    const extraKeys = profileExtraToolInputKeys(profile);
    const auditInput = auditToolInput(toolInput, command, extraKeys);

    const now = (deps.now ?? Date.now)();
    const state = resolveState(deps.state);

    // WR-02. "The server has already told us" is the entire justification for the skip below, so the
    // skip is gated on the server having told *this process* — not on a number a file supplied.
    // `PolicyState.hydrate` never sets this bit, so it is false until the first response that carries
    // `tools_to_check` lands, which the forced pull below guarantees happens on the first real tool
    // call of the session.
    //
    // Without it, a same-UID local process could rewrite the on-disk policy cache as
    // `{tools_to_check: [], tools_synced_at: now}` and disable every file-tool check for 300 s,
    // renewably, while enforcement reported itself active. Cost of the fix is one round trip per
    // session; the warm cache still pays for itself on every call after the first.
    const toolsConfirmed = state.getToolsConfirmed();

    // RES-03's fast path. When the org's own tool list is tools-FRESH and does not name this tool,
    // the server has already told us there is no file policy that could apply — so there is nothing
    // to ask, and no payload is even built. Bounded to the profile's native file tools: a shell
    // command or a custom tool is evaluated on its `command`, which no cached list can answer for.
    if (
      toolsConfirmed &&
      nativeFileTools(profile.fileTools).has(toolName) &&
      shouldSkipFileToolFromState(toolName, state, now, profile.fileTools)
    ) {
      // Recorded, not silent: "we did not ask" is a different audit fact from "we asked and it was
      // allowed", and a turn log that showed them identically would make the cache invisible.
      noteDecision(deps, {
        tool_name: toolName,
        tool_use_id: toolCallId,
        decision: "skipped",
        tool_input: auditInput,
      });
      return { kind: "skip", why: "cached" };
    }

    // `tools_to_check` arrives on the command-policy path ONLY, so a genuine tool call is the only
    // thing that can fill the cache. Ask for it when the list is missing or stale — never by
    // fabricating a request: a synthetic call would be evaluated as a real tool use and can fire an
    // approval for a command nobody ran.
    //
    // An UNCONFIRMED list is always pulled, however fresh its stamp looks (WR-02). That is the
    // self-heal: the first real tool call of the session round-trips, the response re-establishes the
    // list from the server, `toolsConfirmed` flips, and every call after this one takes the TTL logic.
    const pullPolicies = !toolsConfirmed || !areToolsFresh(state.getToolsSyncedAt(), now);

    // The host context is read here and not earlier: a skipped call never needs it.
    const model = source.model;
    const payload = buildPretoolPayload({
      toolName,
      command,
      toolUseId: toolCallId,
      toolInput,
      cwd,
      sessionId: asString(source.sessionId),
      model: typeof model === "string" ? model : undefined,
      clientEntrypoint: asString(deps.entrypoint),
      pullPolicies,
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
      ...(mcp === undefined ? {} : { mcp: { server: mcp.server, tool: mcp.tool ?? "" } }),
      ...(source.patchOperation === "delete" ? { patchOperation: "delete" as const } : {}),
    }, profile);

    const outcome = await check(payload, toolName, deps, state);
    if (outcome === undefined) return { kind: "allow" };

    // Recorded immediately, before the adapter shows anything: the decision is what the POLICY said,
    // and a turn log that waited for a confirm dialog would record the developer's answer instead.
    noteDecision(deps, {
      tool_name: toolName,
      tool_use_id: toolCallId,
      decision: outcome.kind,
      tool_input: auditInput,
    });
    return outcome;
  } catch {
    // An internal fault allows. It must never block.
    return { kind: "allow" };
  }
}

/**
 * Evaluate one user prompt. Total, with the same deadline as `evaluateToolCall`.
 *
 * Skipped without a request: text the host generated (`source: "extension"`), and blank text, which
 * is also how an image-only paste arrives. No decision entry is emitted — a prompt is not a tool call.
 */
export async function evaluatePrompt(input: PromptInput, deps: EvaluateDeps): Promise<ToolEvaluation> {
  try {
    const source: Partial<Record<keyof PromptInput, unknown>> = isRecord(input) ? input : {};
    if (source.source === HOST_GENERATED_SOURCE) return { kind: "skip", why: "nothing-evaluable" };
    const prompt = asString(source.text);
    if (prompt.trim() === "") return { kind: "skip", why: "nothing-evaluable" };

    const state = resolveState(deps.state);
    const model = source.model;
    const payload = buildPromptPayload({
      prompt,
      cwd: asString(source.cwd),
      sessionId: asString(source.sessionId),
      model: typeof model === "string" ? model : undefined,
      clientEntrypoint: asString(deps.entrypoint),
      hasUI: source.hasUI === true,
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
    }, deps.profile);

    // The tool-name argument is only ever used as a telemetry label, so the event name is the
    // informative thing to pass: a bypass on this path is a prompt check, not a tool call.
    const outcome = await check(payload, "user_prompt", deps, state);
    return outcome ?? { kind: "allow" };
  } catch {
    return { kind: "allow" };
  }
}

/**
 * The text for a verdict: what an adapter shows, or raises as its one deliberate error.
 *
 *   * deny         → `DENY_PREFIX + reason`, or `GENERIC_DENY_REASON` when there is no reason
 *   * unavailable  → the reason core supplied, or `ENGINE_UNAVAILABLE_REASON`
 *   * confirm      → the reason, or `GENERIC_DENY_REASON`
 *   * allow / skip → `""`
 *
 * Anything else is `GENERIC_DENY_REASON`: the function is only worth calling on a verdict the
 * adapter is about to block on, so the fallback is a block message, never an empty one.
 *
 * The reason is concatenated after a literal prefix and passed through `sanitizeReason` again here.
 * For a reason that came from core's checker that changes nothing; it is there for a checker that
 * was injected and skipped it.
 */
export function verdictMessage(verdict: ToolEvaluation): string {
  try {
    if (verdict === null || typeof verdict !== "object") return GENERIC_DENY_REASON;
    const kind: unknown = verdict.kind;
    if (kind === "allow" || kind === "skip") return "";
    const reason = sanitizeReason((verdict as { reason?: unknown }).reason);
    if (kind === "deny") return reason === undefined ? GENERIC_DENY_REASON : DENY_PREFIX + reason;
    if (kind === "unavailable") return reason ?? ENGINE_UNAVAILABLE_REASON;
    return reason ?? GENERIC_DENY_REASON;
  } catch {
    return GENERIC_DENY_REASON;
  }
}
