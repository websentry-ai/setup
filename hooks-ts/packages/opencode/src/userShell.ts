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
// `checkUserCommand` is the one decision path for a user command; the v2 entry's
// `shell.create.before` handler (v2Enforce.ts) calls it too.
//
// Caveats (documented in docs/OPENCODE.md): the caller sees a generic HTTP 500 `UnknownError`, and
// the session transcript records the blocked command as `completed` with empty output. The reason is
// toasted (bounded) before the raise, as for prompts. `output.env` is never touched.

import { isAbsolute } from "node:path";

import { USER_BASH_ID_PREFIX } from "../../core/src/constants.ts";
import { evaluateToolCall } from "../../core/src/evaluate.ts";
import type { EvaluateDeps, ToolEvaluation } from "../../core/src/evaluate.ts";
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
    const { runtime } = ctx;
    const sessionID = readString(input, "sessionID");
    const callID = readString(input, "callID");
    if (sessionID === "" || callID === "") return undefined;
    // Model bash: already checked by `tool.execute.before`.
    if (runtime.beforeSeen(sessionID, callID)) return undefined;

    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === undefined || scope === undefined) return undefined;

    const stashed = runtime.takeUserShell(sessionID, callID);
    if (stashed === undefined) {
      runtime.reportSignal(SIGNAL_USER_SHELL_UNCHECKED, "bash", "no_part");
      return undefined;
    }

    return await checkUserCommand(
      stashed.command,
      readString(input, "cwd"),
      sessionID,
      callID,
      ctx,
      stashed.originalChars,
    );
  } catch {
    return undefined;
  }
}

/** What a user command check concluded: the message to block with, and the verdict kind. */
export interface UserCommandDecision {
  message: string | undefined;
  kind: ToolEvaluation["kind"] | undefined;
}

const NO_USER_DECISION: UserCommandDecision = Object.freeze({ message: undefined, kind: undefined });

/**
 * Check one user shell command through core's `evaluateToolCall`, exactly like a model bash call
 * (`toolCallId` = `USER_BASH_ID_PREFIX` + `callID`). Shared by v1 `shell.env` and the v2
 * `shell.create.before` handler (v2Enforce.ts), which knows no session (`sessionID` = `""`: the
 * decision is then not recorded into any turn). A relative or missing cwd is the instance directory.
 * Returns the message to block with, or `undefined`. Total: any fault allows.
 */
export async function checkUserCommand(
  command: string,
  cwdRaw: string,
  sessionID: string,
  callID: string,
  ctx: UserShellContext,
  originalChars?: number,
): Promise<string | undefined> {
  try {
    return (await checkUserCommandVerdict(command, cwdRaw, sessionID, callID, ctx, originalChars)).message;
  } catch {
    return undefined;
  }
}

/** `checkUserCommand` with the verdict kind (the v2 spawn hook treats `unavailable` apart). Total. */
export async function checkUserCommandVerdict(
  command: string,
  cwdRaw: string,
  sessionID: string,
  callID: string,
  ctx: UserShellContext,
  /** The length before an adapter-side cap (the v1 stash); absent when `command` is whole. */
  originalChars?: number,
): Promise<UserCommandDecision> {
  try {
    const { runtime, record } = ctx;
    if (typeof command !== "string" || command === "") return NO_USER_DECISION;
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    if (checker === undefined || scope === undefined) return NO_USER_DECISION;
    // The platform's notion of absolute (a drive-letter or UNC path on Windows), as `narrow.ts` uses
    // for a model shell's `workdir`. A relative or missing cwd is the instance directory.
    const cwd = typeof cwdRaw === "string" && cwdRaw !== "" && isAbsolute(cwdRaw) ? cwdRaw : record.directory;
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
        if (sessionID !== "" && runtime.recordingActive()) runtime.turnFor(sessionID).recordToolCall(entry, sessionID);
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
        model: sessionID === "" ? undefined : runtime.modelFor(sessionID),
        ...(originalChars === undefined ? {} : { commandOriginalChars: originalChars }),
      },
      evalDeps,
    );
    const message = blockingMessage(verdict);
    if (message === undefined) return { message: undefined, kind: verdict.kind };
    // The HTTP caller only sees a generic 500 (V1-7, V2-10): the toast is the clean channel.
    await notify(record.client, message, verdict.kind === "confirm" ? "warning" : "error");
    return { message, kind: verdict.kind };
  } catch {
    return NO_USER_DECISION;
  }
}

/** The registered handler: decide, then block through the single raise site when told to. */
export function shellEnv(ctx: UserShellContext): (input: unknown, output: unknown) => Promise<void> {
  return async (input: unknown, _output: unknown): Promise<void> => {
    const message = await decideUserShell(input, ctx).catch(() => undefined);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}
