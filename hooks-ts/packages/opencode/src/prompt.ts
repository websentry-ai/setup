// `chat.message`: the user-prompt check (HOOK-14), plus model and identity capture (HOOK-17).
//
// Spike V1-5 (13-SPIKES.md): GO. A raise from `chat.message` aborts the prompt before it is persisted
// and before any LLM call, and the host survives. The caller's UX is poor (`run` and sync API callers
// see a generic "Unexpected server error"; async consumers get `session.error`), so the reason is
// toasted first, bounded by `TOAST_TIMEOUT_MS`, and only then raised through the shared `block()`
// helper (which sets `stack = message`, so no plugin path or frame leaks into `session.error`).
//
// What is checked: the non-synthetic `text` parts and the `subtask` part prompts (a subtask slash
// command, 13-REVIEW WR-06) of a prompt in a ROOT session, joined with `\n`.
//   * Synthetic text is host-generated (file attachments rendered as text, compaction notes, the
//     "The following tool was executed by the user" wrapper): not something the user typed.
//   * A child (subagent) session's prompt is written by the parent model through `task`; the parent's
//     own tool calls and the child's tool calls are each enforced on their own.
//   * Root-session decision (13-SPIKES.md): `session.created` reaches `event` before the first
//     `chat.message` of a session, so the parent map (filled from `info.parentID`, truthy only) is
//     authoritative and an unknown session is treated as a root. No session lookup is made.
//
// `decidePrompt` is total: any fault is `undefined` (allow). Nothing is awaited on this path except
// the decision itself and, on a block, the bounded toast.

import { evaluatePrompt } from "../../core/src/evaluate.ts";
import type { EvaluateDeps } from "../../core/src/evaluate.ts";
import { block } from "./block.ts";
import { notify } from "./notify.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { OPENCODE_PROFILE } from "./profile.ts";
import { blockingMessage } from "./verdicts.ts";

export interface PromptContext {
  runtime: Runtime;
  record: DirectoryRecord;
}

/** The most parts of one prompt that are read. A real prompt has a handful. */
const MAX_PROMPT_PARTS = 256;

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

/**
 * The user-typed text of a prompt, joined with `\n`. Total. It is read from:
 *   * non-synthetic `text` parts;
 *   * the `prompt` of `subtask` parts (13-REVIEW WR-06). A slash command whose agent is a subagent,
 *     or that has `subtask: true`, replaces the parts with ONE `{type: "subtask", prompt}` part whose
 *     prompt is the command template with the user's arguments filled in
 *     (`oc:opencode/src/session/prompt.ts:1439-1450`). The prompt then runs as the first message of
 *     a child session, which is never prompt-checked, so this root-session check is its only one.
 */
export function promptTextOf(parts: unknown): string {
  try {
    if (!Array.isArray(parts)) return "";
    const chunks: string[] = [];
    const count = Math.min(parts.length, MAX_PROMPT_PARTS);
    for (let i = 0; i < count; i += 1) {
      const part: unknown = parts[i];
      const type = readField(part, "type");
      if (type === "subtask") {
        const prompt = readField(part, "prompt");
        if (typeof prompt === "string" && prompt !== "") chunks.push(prompt);
        continue;
      }
      if (type !== "text") continue;
      if (readField(part, "synthetic") === true) continue;
      const text = readField(part, "text");
      if (typeof text === "string" && text !== "") chunks.push(text);
    }
    return chunks.join("\n");
  } catch {
    return "";
  }
}

/** `providerID/modelID` from `chat.message`'s `input.model`, or `undefined`. */
function modelOf(input: unknown): { provider: string; model: string } | undefined {
  const model = readField(input, "model");
  const provider = readString(model, "providerID");
  const id = readString(model, "modelID");
  if (provider === "" || id === "") return undefined;
  return { provider, model: `${provider}/${id}` };
}

/**
 * The message to block this prompt with, or `undefined` to let it through. Total: any fault is
 * `undefined`, never a block.
 */
export async function decidePrompt(input: unknown, output: unknown, ctx: PromptContext): Promise<string | undefined> {
  try {
    const { runtime, record } = ctx;
    const resolved = runtime.init();
    const checker = resolved.checker;
    const scope = resolved.scope;
    // No key ⇒ inert (RES-06). The no-key notice is shown by the tool path; a prompt adds nothing.
    if (checker === undefined || scope === undefined) return undefined;

    const sessionID = readString(input, "sessionID");
    const captured = modelOf(input);
    if (captured !== undefined) {
      runtime.setModel(sessionID, captured.model);
      runtime.startIdentity(captured.provider);
    }
    if (runtime.isChild(sessionID)) return undefined;

    const text = promptTextOf(readField(output, "parts"));
    if (text.trim() === "") return undefined;

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
      ...(identity === undefined ? {} : { accountIdentity: identity }),
    };
    const verdict = await evaluatePrompt(
      {
        text,
        source: "interactive",
        cwd: record.directory,
        sessionId: sessionID,
        model: runtime.modelFor(sessionID),
        hasUI: false,
      },
      evalDeps,
    );

    const message = blockingMessage(verdict);
    if (message === undefined) {
      if (runtime.recordingActive()) runtime.turnFor(sessionID).recordPrompt(text, sessionID);
      return undefined;
    }
    // The only clean user-visible channel for a blocked prompt (V1-5): toast first, bounded.
    await notify(record.client, message, verdict.kind === "confirm" ? "warning" : "error");
    return message;
  } catch {
    return undefined;
  }
}

/** The registered handler: decide, then block through the single raise site when told to. */
export function chatMessage(ctx: PromptContext): (input: unknown, output: unknown) => Promise<void> {
  return async (input: unknown, output: unknown): Promise<void> => {
    const message = await decidePrompt(input, output, ctx).catch(() => undefined);
    if (typeof message === "string" && message.length > 0) block(message);
  };
}
