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
// **`event` is deliberately unused.** `AgentEndEvent.messages` is pi's `newMessages` — only what this
// run produced, never the user prompt (`agent-loop.js:142,152,170,182`) — so it cannot be the source
// for the turn log, and the assistant text it does carry is not something the requirement asked us to
// send (see `turnLog.ts`, decision 4). The in-memory record, fed by the `input` and `tool_call` seams,
// is the only source. The parameter stays in the signature because pi passes it and a future reader
// should see that it was considered rather than forgotten.
//
// **The record is taken, not read.** `agent_end` fires again on retries, on
// `stopReason: "error" | "aborted"` and for extension-initiated prompts (§F3), so `take()` empties the
// store and a second fire finds nothing to send. Combined with the empty-turn guard, N fires per
// prompt produce at most one POST.

import type { ApiClient } from "../../core/src/client.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import { buildTurnLogBody, shouldPostTurn } from "../../core/src/turnLog.ts";
import type { TurnStore } from "../../core/src/turn.ts";

/** The structural slice of `AgentEndEvent` — see the header on why nothing is read from it. */
export interface AgentEndLike {
  messages?: unknown[];
}

/** The structural slice of `ExtensionContext` a turn log needs: just the working directory. */
export interface AgentEndCtx {
  cwd: string;
}

export interface AgentEndDeps {
  client: Pick<ApiClient, "postTurnLog">;
  store: TurnStore;
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
}

/** The telemetry label for this path. Not a tool name; the field is a free-form label (§B6). */
const TURNLOG_LABEL = "agent_end";

export function handleAgentEnd(
  _event: AgentEndLike,
  ctx: AgentEndCtx,
  deps: AgentEndDeps,
): undefined {
  try {
    const record = deps.store.take();
    // Nothing to say. pi fires this event for runs that produced no prompt and no tool call at all,
    // and a row describing neither is noise (`PY:4975`).
    if (!shouldPostTurn(record)) return undefined;

    const completedAtMs = (deps.now ?? Date.now)();
    let cwd = "";
    try {
      cwd = typeof ctx?.cwd === "string" ? ctx.cwd : "";
    } catch {
      // A hostile or half-built ctx costs the `cwd` column, not the row.
    }
    const body = buildTurnLogBody(record as NonNullable<typeof record>, { cwd, completedAtMs });
    const dispatchedAtMs = completedAtMs;

    // The whole point of the file: dispatched, not awaited.
    void deps.client
      .postTurnLog(body)
      .then((ok) => {
        if (ok) return;
        deps.telemetry?.reportTurnLogFailure({
          errorClass: "TurnLogFailed",
          toolName: TURNLOG_LABEL,
          elapsedMs: (deps.now ?? Date.now)() - dispatchedAtMs,
        });
      })
      .catch(() => {
        // `postTurnLog` never rejects; this is the belt to its braces. An unhandled rejection in a
        // pi extension is reported as an extension error on every turn.
      });
  } catch {
    // A turn log is telemetry. Nothing about it is worth surfacing to the developer, and this event
    // is awaited — so the fallback is silence, immediately.
  }
  return undefined;
}
