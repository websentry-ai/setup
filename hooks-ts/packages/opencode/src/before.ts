// `tool.execute.before`: the v1 enforcement path (HOOK-08, HOOK-10..13, RES-11).
//
// Every model-issued tool call, in a root or a child (subagent) session, is evaluated through core's
// total `evaluateToolCall`. The registered handler is the only place in this package that raises,
// and only through the shared helper in `block.ts`, with a message from `verdicts.ts`. Everything
// else is total: `decideBefore` returns the message to block with or `undefined`, and its whole body
// is guarded, so a fault here allows (fail-open) and is never a model-visible deny.
//
// Per-tool wire contract (Phase 11 server, 12-REVIEW / 11-REVIEW CR-01):
//   * `bash`: `command`, cwd = absolute `workdir` or the instance directory;
//   * `read` / `write` / `edit` / `lsp`: the real tool-input object, so core's profile taxonomy
//     sends `filePath` as `metadata.file_path` and a differing `path` stays visible in `tool_input`;
//   * `grep` / `glob`: `path` (defaults to cwd) plus `pattern` / `include`;
//   * `apply_patch`: ONE request per header path (`{filePath: target}`, plus
//     `metadata.patch_operation: "delete"` for a `*** Delete File:` target), at most
//     `PATCH_CONCURRENCY` in flight, strictest verdict wins (T-13-22), all under ONE shared
//     deadline (13-REVIEW WR-02); a patch naming more than `MAX_PATCH_TARGETS` files is blocked
//     without a request (13-REVIEW BL-02).
//
// `output.args` is only read and digested here, never reassigned or mutated (Pitfall 5): the digest
// is compared with the executed args in 13-06 (HOOK-18).

import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import {
  EVALUATE_DEADLINE_ERROR_CLASS,
  EVALUATE_DEADLINE_SLACK_MS,
  NO_KEY_NOTICE,
  PRETOOL_TIMEOUT_MS,
} from "../../core/src/constants.ts";
import { evaluateToolCall, noteSafe } from "../../core/src/evaluate.ts";
import type { EvaluateDeps, ToolCallInput, ToolEvaluation } from "../../core/src/evaluate.ts";
import { block } from "./block.ts";
import { auditToolInput, normaliseMcp } from "../../core/src/payload.ts";
import {
  INIT_ERROR_NOTICE,
  MAX_PATCH_TARGETS,
  PATCH_CONCURRENCY,
  SIGNAL_MCP_ATTRIBUTION_AMBIGUOUS,
  SIGNAL_MCP_ATTRIBUTION_MISS,
  SIGNAL_PATCH_TARGETS_CAPPED,
} from "./constants.ts";
import {
  applyPatchDeletedPaths,
  applyPatchTargets,
  argsDigest,
  BUILTIN_TOOLS,
  MCP_RESOURCE_TOOLS,
  mcpCandidates,
  mcpResourceTarget,
  shellCommandOf,
  shellCwdOf,
  SHELL_TOOLS,
  TASK_TOOL,
} from "./narrow.ts";
import { notify } from "./notify.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { OPENCODE_PROFILE } from "./profile.ts";
import { blockingMessage, strictest } from "./verdicts.ts";

/** What plugin.ts hands the handler: the plugin copy's runtime and this directory's record. */
export interface BeforeContext {
  runtime: Runtime;
  record: DirectoryRecord;
  /**
   * Where a shell call runs, when the host's own resolution of a relative `workdir` is known (v2:
   * resolved under the session's directory). Absent: `shellCwdOf` (absolute `workdir` or the
   * instance directory). Only the checked cwd changes; the call's arguments are never rewritten.
   */
  shellCwd?: string;
}

const APPLY_PATCH_TOOL = "apply_patch";
/** `setTimeout` treats a larger delay as 1 ms. */
const MAX_TIMER_MS = 2_147_483_647;

/** Why an `apply_patch` naming more files than `MAX_PATCH_TARGETS` is refused (13-REVIEW BL-02). */
export const PATCH_TOO_LARGE_REASON =
  `patch too large to verify: it names more than ${MAX_PATCH_TARGETS} files, ` +
  "so some of them could not be checked. Split it into smaller patches.";

function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function readString(value: unknown, key: string): string {
  const field = readField(value, key);
  return typeof field === "string" ? field : "";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** What `fanOut` needs besides the checks themselves. */
interface FanOutDeps {
  /** The ONE deadline for the whole fan-out; resolved like core's per-check deadline. */
  deadlineMs: number | undefined;
  /** The org's last-known `policy_check_failure_action` (`"block"` = fail-closed). */
  failureAction(): string | undefined;
  /** Where an expired fan-out is reported, like core reports an expired single check. */
  telemetry: EvaluateDeps["telemetry"];
  /** Receives the one audit entry an expired fan-out leaves. */
  onDecision: EvaluateDeps["onDecision"];
  /** The checker label (`toolName`) and the call id the expiry is reported and recorded under. */
  label: string;
  callID: string;
}

/** Core's per-check deadline rule: a positive finite override, else `PRETOOL_TIMEOUT_MS` + slack. */
function fanOutDeadlineMs(raw: number | undefined): number {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return Math.min(raw, MAX_TIMER_MS);
  return PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS;
}

/**
 * Run the checks for `items` (at most `limit` in flight) under ONE shared deadline and return the
 * strictest verdict (13-REVIEW WR-02). Without the shared deadline every check carried its own 20 s
 * bound, so a slow gateway could hold a 200-file patch for about ⌈200 / 8⌉ × 20 s.
 *
 * On expiry no further check is started, and the answer is the strictest of the verdicts already in
 * plus the org's failure action for the rest: `unavailable` for a fail-closed org, else `allow`. A
 * deny that already arrived therefore still blocks. The expiry is reported as core reports an expired
 * single check (`reportBypass`, `EvaluateDeadline`, `blocked` for a fail-closed org) and recorded once.
 * Total: resolves for any input.
 */
async function fanOut<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<ToolEvaluation>,
  deps: FanOutDeps,
): Promise<ToolEvaluation> {
  const results: ToolEvaluation[] = [];
  let next = 0;
  let expired = false;
  const worker = async (): Promise<void> => {
    while (!expired && next < items.length) {
      const index = next;
      next += 1;
      const verdict = await fn(items[index] as T).catch((): ToolEvaluation => ({ kind: "allow" }));
      if (!expired) results.push(verdict);
    }
  };
  const deadlineMs = fanOutDeadlineMs(deps.deadlineMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Not unref'd, like core's own deadline: while a check is outstanding this timer IS the bound.
  const timedOut = new Promise<"timed-out">((resolve) => {
    timer = setTimeout(() => resolve("timed-out"), deadlineMs);
  });
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.max(1, Math.min(limit, items.length)); i += 1) workers.push(worker());
  const done = Promise.all(workers).then(() => "done" as const, () => "done" as const);
  const raced = await Promise.race([done, timedOut]);
  if (timer !== undefined) clearTimeout(timer);
  if (raced === "done") return strictest(results);

  expired = true;
  const blocked = deps.failureAction() === "block";
  const rest: ToolEvaluation = blocked ? { kind: "unavailable" } : { kind: "allow" };
  noteSafe(() =>
    deps.telemetry?.reportBypass({
      errorClass: EVALUATE_DEADLINE_ERROR_CLASS,
      toolName: deps.label,
      elapsedMs: deadlineMs,
      blocked,
    }),
  );
  const verdict = strictest([...results, rest]);
  noteSafe(() =>
    deps.onDecision?.({
      tool_name: deps.label,
      tool_use_id: deps.callID,
      decision: verdict.kind,
      tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys),
    }),
  );
  return verdict;
}

/**
 * What `decideBeforeVerdict` concluded: the message to block with (or `undefined` to let the call
 * run), the verdict kind it came from, and the verdict's own reason. `kind` is `undefined` when no
 * verdict was reached (no key, init fault, `task`, a fault). The v2 entry needs the kind and reason
 * to pick its lever (evaluate deny vs native ask vs raise, 14-SPIKES HV2-02/03/04); v1 needs only
 * the message.
 */
export interface BeforeDecision {
  message: string | undefined;
  kind: ToolEvaluation["kind"] | undefined;
  reason?: string;
}

const NO_DECISION: BeforeDecision = Object.freeze({ message: undefined, kind: undefined });

function reasonOf(verdict: ToolEvaluation): string | undefined {
  try {
    const reason: unknown = (verdict as { reason?: unknown }).reason;
    return typeof reason === "string" && reason !== "" ? reason : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The decision for this call. Total: any fault is `NO_DECISION` (allow), never a block.
 */
export async function decideBeforeVerdict(input: unknown, output: unknown, ctx: BeforeContext): Promise<BeforeDecision> {
  try {
    const { runtime, record } = ctx;
    // First thing: this call is model-issued, so `shell.env` must never check it again (HOOK-19).
    runtime.markBeforeSeen(readString(input, "sessionID"), readString(input, "callID"));
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    // No key ⇒ inert (RES-06); a resolution fault ⇒ degraded (WR-03). Either way: no request, no
    // verdict, and one notice per directory that names the actual cause.
    if (checker === undefined || scope === undefined) {
      if (resolved.status === "init_error") {
        if (!record.initErrorNoticeShown) {
          record.initErrorNoticeShown = true;
          void notify(record.client, INIT_ERROR_NOTICE, "warning");
        }
        return NO_DECISION;
      }
      const instance = runtime.instances.forDirectory(record.directory);
      if (!instance.noKeyNoticeShown) {
        instance.noKeyNoticeShown = true;
        void notify(record.client, NO_KEY_NOTICE, "info");
      }
      return NO_DECISION;
    }

    const tool = readString(input, "tool");
    const sessionID = readString(input, "sessionID");
    const callID = readString(input, "callID");
    const rawArgs = readField(output, "args");
    const args: Record<string, unknown> = isPlainObject(rawArgs) ? rawArgs : {};
    const directory = record.directory;

    // `task` (HOOK-11): audited, never sent for a decision, so it can never be denied. A deny here
    // would strand the subtask part: opencode triggers the subtask outside the tool's error capture
    // (Pitfall 12). The child session's own tool calls are each enforced on their own.
    if (tool === TASK_TOOL) {
      if (runtime.recordingActive()) {
        noteSafe(() =>
          runtime.turnFor(sessionID).recordToolCall(
            {
              tool_name: TASK_TOOL,
              tool_use_id: callID,
              decision: "audited",
              tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys),
            },
            sessionID,
          ),
        );
      }
      return NO_DECISION;
    }

    // MCP (HOOK-13): attribution only from the call's own server argument (resource tools) or the
    // longest known server-name prefix; never by splitting the id. Every call that goes to a tool
    // server (any non-built-in id, and the MCP resource tools) is SENT, attributed or not
    // (13-REVIEW BL-01): an MCP server added at runtime, a server name over the attribution cap, or a
    // plugin tool still reaches the server, which logs the attribution miss and applies what it can.
    // The miss is reported here too, whether or not any MCP server is configured.
    const builtin = BUILTIN_TOOLS.has(tool);
    const toolServerCall = tool !== "" && (!builtin || MCP_RESOURCE_TOOLS.has(tool));
    const resourceMcp = mcpResourceTarget(tool, args);
    // 13-REVIEW WR-01: sanitised keys can collide (`github` + `create_issue` and `github_create` +
    // `issue` both give `github_create_issue`), and opencode keeps whichever client registered last,
    // which the adapter cannot see. So every server that could have produced the id is a candidate.
    const candidates =
      resourceMcp !== undefined || builtin || tool === "" ? [] : mcpCandidates(tool, runtime.mcpServerNamesFor(record));
    const mcp = resourceMcp ?? candidates[0];
    if (candidates.length > 1) {
      runtime.reportSignal(SIGNAL_MCP_ATTRIBUTION_AMBIGUOUS, tool, `candidates_${candidates.length}`);
    }
    if (toolServerCall) {
      const attributed = mcp !== undefined && normaliseMcp(mcp) !== undefined;
      if (!attributed) {
        runtime.reportSignal(SIGNAL_MCP_ATTRIBUTION_MISS, tool, mcp === undefined ? "unresolved" : "name_over_cap");
        // A server added at runtime is only in the host's live list: refresh it for later calls.
        if (mcp === undefined && !builtin) runtime.refreshMcpNames(record);
      }
    }

    const identity: AccountIdentity | undefined = runtime.identity();
    const deadlineMs = runtime.deps.deadlineMs;
    const evalDeps: EvaluateDeps = {
      checker,
      profile: OPENCODE_PROFILE,
      entrypoint: runtime.entrypoint(),
      state: scope.policy,
      now: runtime.deps.now,
      ...(deadlineMs === undefined ? {} : { deadlineMs }),
      ...(resolved.telemetry === undefined ? {} : { telemetry: resolved.telemetry }),
      hooks: {
        notify: (message, level) => {
          void notify(record.client, message, level);
        },
      },
      // Re-checked per decision: the checker may latch the key on this very call.
      onDecision: (entry) => {
        if (runtime.recordingActive()) runtime.turnFor(sessionID).recordToolCall(entry, sessionID);
      },
      ...(identity === undefined ? {} : { accountIdentity: identity }),
    };
    const model = runtime.modelFor(sessionID);

    let verdict: ToolEvaluation;
    if (tool === APPLY_PATCH_TOOL) {
      const { targets, capped } = applyPatchTargets(args.patchText);
      if (capped) {
        // 13-REVIEW BL-02: files past the cap would run unchecked (opencode applies the whole patch),
        // so a patch naming more files than can be verified is refused outright. A deliberate,
        // deterministic verdict on the model's own input, not an error path; no request is made.
        runtime.reportSignal(SIGNAL_PATCH_TARGETS_CAPPED, tool, "blocked");
        verdict = { kind: "deny", reason: PATCH_TOO_LARGE_REASON };
        noteSafe(() =>
          evalDeps.onDecision?.({
            tool_name: APPLY_PATCH_TOOL,
            tool_use_id: callID,
            decision: "deny",
            tool_input: auditToolInput({}, "", OPENCODE_PROFILE.extraToolInputKeys),
          }),
        );
        const message = blockingMessage(verdict);
        if (message !== undefined) void notify(record.client, message, "error");
        return { message, kind: "deny", reason: PATCH_TOO_LARGE_REASON };
      }
      // A per-file request carries no patch text, so a deleted target says so itself (ai-gateway
      // Phase 11 contract: `metadata.patch_operation: "delete"`, else it is classified as a write).
      const deleted = applyPatchDeletedPaths(args.patchText);
      verdict = await fanOut(
        targets,
        PATCH_CONCURRENCY,
        (target) =>
          evaluateToolCall(
            {
              toolName: APPLY_PATCH_TOOL,
              toolCallId: callID,
              command: "",
              toolInput: { filePath: target },
              cwd: directory,
              sessionId: sessionID,
              model,
              ...(deleted.has(target) ? { patchOperation: "delete" as const } : {}),
            },
            evalDeps,
          ),
        {
          deadlineMs,
          failureAction: () => scope.policy.getFailureAction(),
          telemetry: resolved.telemetry,
          onDecision: evalDeps.onDecision,
          label: APPLY_PATCH_TOOL,
          callID,
        },
      );
    } else if (candidates.length > 1) {
      // Ambiguous MCP attribution (WR-01): check the call once per candidate server, under one shared
      // deadline, and let the strictest verdict decide, so a policy on any of them applies.
      verdict = await fanOut(
        candidates,
        PATCH_CONCURRENCY,
        (candidate) =>
          evaluateToolCall(
            {
              toolName: tool,
              toolCallId: callID,
              command: "",
              toolInput: args,
              cwd: directory,
              sessionId: sessionID,
              model,
              mcp: candidate,
              sendUnattributed: true,
            },
            evalDeps,
          ),
        {
          deadlineMs,
          failureAction: () => scope.policy.getFailureAction(),
          telemetry: resolved.telemetry,
          onDecision: evalDeps.onDecision,
          label: tool,
          callID,
        },
      );
    } else {
      const call: ToolCallInput = {
        toolName: tool,
        toolCallId: callID,
        command: shellCommandOf(tool, args),
        toolInput: args,
        cwd: SHELL_TOOLS.has(tool)
          ? typeof ctx.shellCwd === "string" && ctx.shellCwd !== ""
            ? ctx.shellCwd
            : shellCwdOf(args, directory)
          : directory,
        sessionId: sessionID,
        model,
        ...(mcp === undefined ? {} : { mcp }),
        ...(toolServerCall ? { sendUnattributed: true } : {}),
      };
      verdict = await evaluateToolCall(call, evalDeps);
    }

    // deny → the deny text; confirm (ask / approval_required) → the approval text, because v1 cannot
    // ask; unavailable → core's engine-unavailable text, which core only returns for a fail-closed
    // org. RES-11: core files that case as `blocked_due_to_failure` and a fail-open failure as
    // `bypassed_due_to_failure` (`reportBypass({ blocked })`), so the two never share a category.
    const message = blockingMessage(verdict);
    if (message === undefined) {
      runtime.rememberDigest(sessionID, callID, argsDigest(rawArgs));
      return { message: undefined, kind: verdict.kind };
    }
    if (verdict.kind === "deny") void notify(record.client, message, "error");
    else if (verdict.kind === "confirm") void notify(record.client, message, "warning");
    const reason = reasonOf(verdict);
    return reason === undefined ? { message, kind: verdict.kind } : { message, kind: verdict.kind, reason };
  } catch {
    return NO_DECISION;
  }
}

/**
 * The message to block this call with, or `undefined` to let it run. Total: any fault is
 * `undefined` (allow), never a block.
 */
export async function decideBefore(input: unknown, output: unknown, ctx: BeforeContext): Promise<string | undefined> {
  try {
    return (await decideBeforeVerdict(input, output, ctx)).message;
  } catch {
    return undefined;
  }
}

/** The registered handler: decide, then block through the single raise site when told to. */
export function toolExecuteBefore(ctx: BeforeContext): (input: unknown, output: unknown) => Promise<void> {
  return async (input: unknown, output: unknown): Promise<void> => {
    const message = await decideBefore(input, output, ctx).catch(() => undefined);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}
