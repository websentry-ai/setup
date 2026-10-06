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
//   * `apply_patch`: ONE request per header path (`{filePath: target}`), at most
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
  MAX_PATCH_TARGETS,
  PATCH_CONCURRENCY,
  SIGNAL_MCP_ATTRIBUTION_MISS,
  SIGNAL_PATCH_TARGETS_CAPPED,
} from "./constants.ts";
import {
  applyPatchTargets,
  argsDigest,
  BUILTIN_TOOLS,
  MCP_RESOURCE_TOOLS,
  mcpResourceTarget,
  resolveMcpTool,
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
 * The message to block this call with, or `undefined` to let it run. Total: any fault is
 * `undefined` (allow), never a block.
 */
export async function decideBefore(input: unknown, output: unknown, ctx: BeforeContext): Promise<string | undefined> {
  try {
    const { runtime, record } = ctx;
    // First thing: this call is model-issued, so `shell.env` must never check it again (HOOK-19).
    runtime.markBeforeSeen(readString(input, "sessionID"), readString(input, "callID"));
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    // No key ⇒ inert (RES-06): no request, no verdict, one notice per directory.
    if (checker === undefined || scope === undefined) {
      const instance = runtime.instances.forDirectory(record.directory);
      if (!instance.noKeyNoticeShown) {
        instance.noKeyNoticeShown = true;
        void notify(record.client, NO_KEY_NOTICE, "info");
      }
      return undefined;
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
      return undefined;
    }

    // MCP (HOOK-13): attribution only from the call's own server argument (resource tools) or the
    // longest known server-name prefix; never by splitting the id. Every call that goes to a tool
    // server (any non-built-in id, and the MCP resource tools) is SENT, attributed or not
    // (13-REVIEW BL-01): an MCP server added at runtime, a server name over the attribution cap, or a
    // plugin tool still reaches the server, which logs the attribution miss and applies what it can.
    // The miss is reported here too, whether or not any MCP server is configured.
    const builtin = BUILTIN_TOOLS.has(tool);
    const toolServerCall = tool !== "" && (!builtin || MCP_RESOURCE_TOOLS.has(tool));
    const mcp =
      mcpResourceTarget(tool, args) ??
      (builtin || tool === "" ? undefined : resolveMcpTool(tool, runtime.mcpServerNamesFor(record)));
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
        return message;
      }
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
    } else {
      const call: ToolCallInput = {
        toolName: tool,
        toolCallId: callID,
        command: shellCommandOf(tool, args),
        toolInput: args,
        cwd: SHELL_TOOLS.has(tool) ? shellCwdOf(args, directory) : directory,
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
      return undefined;
    }
    if (verdict.kind === "deny") void notify(record.client, message, "error");
    else if (verdict.kind === "confirm") void notify(record.client, message, "warning");
    return message;
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
