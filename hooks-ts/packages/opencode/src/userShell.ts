// `shell.env`: the user `!cmd` check (HOOK-19). Spike V1-7 (13-SPIKES.md): GO, with caveats.
//
// opencode's user shell (`POST /session/:id/shell`, the TUI `!cmd`) persists a `bash` tool part
// carrying `state.input.command`, publishes it on the bus, and only then fires `shell.env` with
// `{cwd, sessionID, callID}` and NO command (`oc:opencode/src/session/prompt.ts:505-558`). The event
// handler stashes that command by callID synchronously (record.ts); here it is taken and checked
// through core's `evaluateToolCall` exactly like a model bash call. A raise from `shell.env`
// prevented the spawn in every spike repeat.
//
// `shell.env` also fires for the MODEL's bash tool, after `tool.execute.before` already checked it:
// such a call is marked "before seen" and is never checked twice. A `shell.env` with a callID but
// nothing stashed is reported as `user_shell_unchecked` (detail `no_part`) and allowed. One with no
// session or call id (a spawn we cannot correlate) is left alone.
//
// Caveats (documented in docs/OPENCODE.md): the caller sees a generic HTTP 500 `UnknownError`, and
// the session transcript records the blocked command as `completed` with empty output. The reason is
// toasted (bounded) before the raise, as for prompts. `output.env` is never touched.

import { USER_BASH_ID_PREFIX } from "../../core/src/constants.ts";
import { evaluateToolCall } from "../../core/src/evaluate.ts";
import type { EvaluateDeps } from "../../core/src/evaluate.ts";
import { block } from "./block.ts";
import { SIGNAL_USER_SHELL_UNCHECKED } from "./constants.ts";
import { notify } from "./notify.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { OPENCODE_PROFILE } from "./profile.ts";
import { blockingMessage } from "./verdicts.ts";

export interface UserShellContext {
  runtime: Runtime;
  record: DirectoryRecord;
}

function readString(value: unknown, key: string): string {
  try {
    if (value === null || typeof value !== "object") return "";
    const field: unknown = (value as Record<string, unknown>)[key];
    return typeof field === "string" ? field : "";
  } catch {
    return "";
  }
}

/**
 * The message to block this user command with, or `undefined` to let it run. Total: any fault is
 * `undefined` (allow), never a block.
 */
export async function decideUserShell(input: unknown, ctx: UserShellContext): Promise<string | undefined> {
  try {
    const { runtime, record } = ctx;
    const sessionID = readString(input, "sessionID");
    const callID = readString(input, "callID");
    if (sessionID === "" || callID === "") return undefined;
    // Model bash: already checked by `tool.execute.before`.
    if (runtime.beforeSeen(sessionID, callID)) return undefined;

    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === undefined || scope === undefined) return undefined;

    const command = runtime.takeUserShell(sessionID, callID);
    if (command === undefined) {
      runtime.reportSignal(SIGNAL_USER_SHELL_UNCHECKED, "bash", "no_part");
      return undefined;
    }

    const cwdRaw = readString(input, "cwd");
    const cwd = cwdRaw.startsWith("/") ? cwdRaw : record.directory;
    const identity = runtime.identity();
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
      onDecision: (entry) => {
        if (runtime.recordingActive()) runtime.turnFor(sessionID).recordToolCall(entry, sessionID);
      },
      ...(identity === undefined ? {} : { accountIdentity: identity }),
    };
    const verdict = await evaluateToolCall(
      {
        toolName: "bash",
        toolCallId: USER_BASH_ID_PREFIX + callID,
        command,
        toolInput: {},
        cwd,
        sessionId: sessionID,
        model: runtime.modelFor(sessionID),
      },
      evalDeps,
    );
    const message = blockingMessage(verdict);
    if (message === undefined) return undefined;
    // The HTTP caller only sees a generic 500 (V1-7): the toast is the clean channel.
    await notify(record.client, message, verdict.kind === "confirm" ? "warning" : "error");
    return message;
  } catch {
    return undefined;
  }
}

/** The registered handler: decide, then block through the single raise site when told to. */
export function shellEnv(ctx: UserShellContext): (input: unknown, output: unknown) => Promise<void> {
  return async (input: unknown, _output: unknown): Promise<void> => {
    const message = await decideUserShell(input, ctx).catch(() => undefined);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}
