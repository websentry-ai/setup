// RES-04 — the `agent_end` adapter. One turn finished; post a description of it, best-effort.
//
// **This handler must return synchronously, and that is not a style preference.**
// `AC/dist/types.d.ts:418-421`: "`agent_end` is the last event emitted for a run, but awaited
// `Agent.subscribe()` listeners for that event are still part of run settlement. The agent becomes
// idle only after those listeners finish." Awaiting a 10 s POST would therefore make pi look busy for
// up to 10 s after **every** turn — a self-inflicted denial of service on the developer's own agent
// (T-09-22). So the POST is dispatched with `void … .catch(…)` and `undefined` is returned
// immediately; `agentEnd.test.ts` measures the handler against a hanging endpoint and fails above
// 50 ms. There is no `await` on `postTurnLog` anywhere in this file or in `index.ts`.
//
// **`event` is read for exactly one thing: the assistant text.** `AgentEndEvent.messages` is pi's
// `newMessages` — only what this run produced, never the user prompt
// (`agent-loop.js:142,152,170,182`) — so it cannot be the source for the prompt or the tool calls;
// those come from the in-memory record, fed by the `input` and `tool_call` seams. What it *does* carry
// is what the model said, and that used to be dropped on the floor, leaving every row with a silent
// assistant (see `turnLog.ts`, decision 4).
//
// `assistantTextFrom` is the whole of that reading, and it is deliberately narrow: `role:"assistant"`
// messages only, `type:"text"` parts only. Thinking parts are excluded because provider reasoning is
// not the answer and is the most sensitive thing in the array; `toolCall` parts are excluded because
// their arguments are the raw, UN-allowlisted tool input the turn log carries a sanitised projection
// of — forwarding them here would have re-opened the egress `tool_input` closes one layer down. The
// text is never stored in the turn record and never logged; it is passed to the body builder, capped
// there, and lives only as long as the POST.
//
// **The record is taken, not read.** `agent_end` fires again on retries, on
// `stopReason: "error" | "aborted"` and for extension-initiated prompts (§F3), so `take()` empties the
// store and a second fire finds nothing to send. Combined with the empty-turn guard, N fires per
// prompt produce at most one POST.
//
// **`postStandaloneTurn` is the second source of turn logs**, for `!cmd`. pi fires no `agent_end` for
// a typed command, so its decision is posted as its own one-call row the moment it is made, through
// the same not-awaited dispatch (`dispatchTurnLog`), and never written into the shared store.

import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import type { ApiClient } from "../../core/src/client.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import { buildTurnLogBody, shouldPostTurn } from "../../core/src/turnLog.ts";
import type { TurnRecord, TurnStore, TurnToolCall } from "../../core/src/turn.ts";

/**
 * The structural slice of `AgentEndEvent`: pi's `messages`, typed as `unknown[]` on purpose.
 *
 * `AgentMessage` is a union that includes host-registered custom message types, so its `content` is
 * genuinely not a fixed shape at this boundary — narrowing it structurally in `assistantTextFrom` is
 * what makes reading it safe, rather than a cast that would compile and then find a string where an
 * array was promised.
 */
export interface AgentEndLike {
  messages?: unknown[];
}

/**
 * The assistant's own words for this turn, joined and bounded — or `""`.
 *
 * Multiple assistant messages are normal for one run (a tool batch splits the answer in two), so they
 * are joined with `\n` in arrival order, as are multiple text parts within one message. Everything
 * else in the array is skipped: user and tool-result messages, `thinking` parts, and `toolCall` parts
 * whose `arguments` are exactly the raw input the turn log deliberately allowlists.
 *
 * Total, like every other function reachable from a handler. Exported for `agentEnd.test.ts`, which
 * asserts the part-by-part filtering directly rather than inferring it from a posted body.
 */
export function assistantTextFrom(messages: unknown): string {
  try {
    const list = Array.isArray(messages) ? messages : [];
    const chunks: string[] = [];
    for (const message of list) {
      if (message === null || typeof message !== "object") continue;
      const { role, content } = message as { role?: unknown; content?: unknown };
      if (role !== "assistant") continue;
      // pi types an assistant message's content as an array of parts, always
      // (`pi-ai/types.d.ts:353-355`); only `UserMessage` may carry a bare string. A string here is
      // therefore a shape pi does not produce, and guessing at it is how a `user` message's text
      // would end up attributed to the model.
      if (!Array.isArray(content)) continue;
      const parts: string[] = [];
      for (const part of content) {
        if (part === null || typeof part !== "object") continue;
        const { type, text } = part as { type?: unknown; text?: unknown };
        if (type !== "text") continue;
        if (typeof text !== "string" || text === "") continue;
        parts.push(text);
      }
      if (parts.length > 0) chunks.push(parts.join("\n"));
    }
    return chunks.join("\n");
  } catch {
    // A message array we cannot read costs the assistant column. The row still goes.
    return "";
  }
}

/** The structural slice of `ExtensionContext` a turn log needs: just the working directory. */
export interface AgentEndCtx {
  cwd: string;
}

export interface AgentEndDeps {
  client: Pick<ApiClient, "postTurnLog">;
  store: TurnStore;
  /** Optional: the session key, scrubbed from assistant text and commands before they are posted. */
  apiKey?: string;
  /**
   * Optional: one rate-limited report when a post fails, so a permanently broken audit trail is
   * visible in Sentry rather than silent.
   *
   * Narrowed to `reportTurnLogFailure`, which is not a style choice — it is what makes the rule
   * enforceable. A failed turn log is a lost row, not a skipped enforcement, and both of
   * `reportBypass`'s categories feed the "enforcement was silently skipped" alert. This route 404s
   * until the Phase 7 backend ships, so filing lost rows there would bury every genuine fail-open
   * event under noise from a route that enforces nothing. Typing the dependency this way means this
   * file **cannot reach** the bypass reporter, rather than merely choosing not to.
   */
  telemetry?: Pick<Telemetry, "reportTurnLogFailure">;
  now?: () => number;
  /** The process's settled account identity, attached to the turn log as `account_identity`. */
  accountIdentity?: AccountIdentity;
}

/** The telemetry label for this path. Not a tool name; the field is a free-form label (§B6). */
const TURNLOG_LABEL = "agent_end";

/** The telemetry label for a standalone `!cmd` row, so its failures are distinguishable. */
const USER_BASH_LABEL = "user_bash";

/** `ctx.cwd`, read behind a guard: a hostile or half-built ctx costs the `cwd` column, not the row. */
function cwdOf(ctx: { cwd?: unknown } | undefined): string {
  try {
    return typeof ctx?.cwd === "string" ? ctx.cwd : "";
  } catch {
    return "";
  }
}

/**
 * Build the body for `record` and dispatch it, fire-and-forget — the one code path both turn-log
 * sources share, so the "never awaited, failure reported under a label" contract has a single place
 * to be true.
 *
 * Returns nothing and never a promise: the POST settles on its own time under its own deadline, and a
 * failure is one rate-limited `reportTurnLogFailure` under `label`. Total — every caller is on a path
 * pi awaits.
 */
function dispatchTurnLog(
  record: TurnRecord,
  cwd: string,
  assistantText: string,
  label: string,
  deps: Omit<AgentEndDeps, "store">,
): void {
  try {
    const completedAtMs = (deps.now ?? Date.now)();
    const body = buildTurnLogBody(record, {
      cwd,
      completedAtMs,
      assistantText,
      ...(deps.apiKey === undefined ? {} : { apiKey: deps.apiKey }),
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
    });
    const dispatchedAtMs = completedAtMs;

    // The whole point of the file: dispatched, not awaited.
    void deps.client
      .postTurnLog(body)
      .then((ok) => {
        if (ok) return;
        deps.telemetry?.reportTurnLogFailure({
          errorClass: "TurnLogFailed",
          toolName: label,
          elapsedMs: (deps.now ?? Date.now)() - dispatchedAtMs,
        });
      })
      .catch(() => {
        // `postTurnLog` never rejects; this is the belt to its braces. An unhandled rejection in a
        // pi extension is reported as an extension error on every turn.
      });
  } catch {
    // A turn log is telemetry — see `handleAgentEnd`.
  }
}

export function handleAgentEnd(
  event: AgentEndLike,
  ctx: AgentEndCtx,
  deps: AgentEndDeps,
): undefined {
  try {
    const record = deps.store.take();
    // Nothing to say. pi fires this event for runs that produced no prompt and no tool call at all,
    // and a row describing neither is noise (`PY:4975`).
    if (!shouldPostTurn(record)) return undefined;

    let assistantText = "";
    try {
      assistantText = assistantTextFrom(event?.messages);
    } catch {
      // `assistantTextFrom` is already total; this catches a throwing `messages` getter, which would
      // otherwise lose the whole row to a field that is only a column.
    }
    dispatchTurnLog(record as NonNullable<typeof record>, cwdOf(ctx), assistantText, TURNLOG_LABEL, deps);
  } catch {
    // A turn log is telemetry. Nothing about it is worth surfacing to the developer, and this event
    // is awaited — so the fallback is silence, immediately.
  }
  return undefined;
}

/** The decision entry a standalone row describes — structurally `decide.ts`'s `DecisionEntry`. */
export interface StandaloneTurnEntry {
  tool_name: string;
  tool_use_id: string;
  decision: string;
  tool_input?: Record<string, unknown>;
}

/**
 * Post ONE call as its own turn log, immediately — the `!cmd` (`user_bash`) path.
 *
 * pi fires no `agent_end` for a bare `!cmd`, so recording it into the shared turn store meant it sat
 * there until the NEXT agent turn posted it, under that turn's prompt — a row claiming the developer's
 * typed command was part of a conversation it had nothing to do with. So a `!cmd` never enters the
 * store: its decision is wrapped in a one-call record here and dispatched through the same
 * fire-and-forget path `agent_end` uses.
 *
 * The record carries **no `prompt`**: a `!cmd` has none, and inventing one would mislabel the row. It
 * is still postable, because `shouldPostTurn` accepts a record with one tool call. `assistantText` is
 * `""` for the same reason. Never awaits, never returns a promise, never throws.
 */
export function postStandaloneTurn(
  entry: StandaloneTurnEntry,
  ctx: { cwd?: unknown } | undefined,
  sessionId: string,
  deps: Omit<AgentEndDeps, "store">,
): undefined {
  try {
    if (entry === null || typeof entry !== "object") return undefined;
    const now = (deps.now ?? Date.now)();
    const call: TurnToolCall = {
      tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
      tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
      decision: typeof entry.decision === "string" ? entry.decision : "",
      ts: now,
    };
    const input = entry.tool_input;
    if (input !== null && typeof input === "object" && !Array.isArray(input)) {
      call.tool_input = { ...input };
    }
    const record: TurnRecord = { tool_calls: [call], results: [], started_at: now };
    if (typeof sessionId === "string" && sessionId !== "") {
      record.session_id = sessionId;
      call.session_id = sessionId;
    }
    if (!shouldPostTurn(record)) return undefined;
    dispatchTurnLog(record, cwdOf(ctx), "", USER_BASH_LABEL, deps);
  } catch {
    // Telemetry. On this path a throw would escape into `user_bash`, where pi silently declines to
    // run the command — `noteDecision` guards that too, and this is the belt to its braces.
  }
  return undefined;
}
