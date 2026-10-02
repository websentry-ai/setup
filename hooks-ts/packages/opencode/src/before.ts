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
//     `PATCH_CONCURRENCY` in flight, strictest verdict wins (T-13-22).
//
// `output.args` is only read and digested here, never reassigned or mutated (Pitfall 5): the digest
// is compared with the executed args in 13-06 (HOOK-18).

import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import { NO_KEY_NOTICE } from "../../core/src/constants.ts";
import { evaluateToolCall, noteSafe } from "../../core/src/evaluate.ts";
import type { EvaluateDeps, ToolCallInput, ToolEvaluation } from "../../core/src/evaluate.ts";
import { block } from "./block.ts";
import { auditToolInput } from "../../core/src/payload.ts";
import { PATCH_CONCURRENCY, SIGNAL_MCP_ATTRIBUTION_MISS, SIGNAL_PATCH_TARGETS_CAPPED } from "./constants.ts";
import {
  applyPatchTargets,
  argsDigest,
  BUILTIN_TOOLS,
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

/** Run `fn` over `items` with at most `limit` in flight; results in input order. Total. */
async function mapBounded<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index] as T);
    }
  };
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.max(1, Math.min(limit, items.length)); i += 1) workers.push(worker());
  await Promise.all(workers);
  return results;
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
    // longest configured server-name prefix; never by splitting the id. A non-built-in tool that
    // matches no configured server is reported and evaluated without MCP metadata (core then skips
    // it as nothing-evaluable unless it carries something else the server evaluates).
    const builtin = BUILTIN_TOOLS.has(tool);
    const mcp = mcpResourceTarget(tool, args) ?? (builtin ? undefined : resolveMcpTool(tool, record.mcpServerNames));
    if (mcp === undefined && !builtin && record.mcpServerNames.length > 0) {
      runtime.reportSignal(SIGNAL_MCP_ATTRIBUTION_MISS, tool, "unresolved");
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
      if (capped) runtime.reportSignal(SIGNAL_PATCH_TARGETS_CAPPED, tool, "capped");
      const verdicts = await mapBounded(targets, PATCH_CONCURRENCY, (target) =>
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
      );
      verdict = strictest(verdicts);
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
