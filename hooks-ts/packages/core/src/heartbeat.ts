// RES-05 — the `session_start` heartbeat: the payload, and the rate limit that makes it safe.
//
// **What this heartbeat is for, and what it is not.** It announces a session and warms
// `policy_check_failure_action` — the org's opt-out from fail-open, which is read regardless of age
// (`unbound.py:225`) and is the one thing that can turn an API failure into a block. It does **not**
// fetch `tools_to_check`: no heartbeat shape available today returns it. `event_name: 'session_start'`
// with a blank `tool_name` lands on the fall-through at `preToolUseHandler.ts:1008-1012`, which
// carries no policy payload at all, and the `user_prompt` path deliberately omits the field so a
// prompt check cannot clobber the tool cache (`:1399-1405`). The tool list is therefore pulled on the
// first genuine tool call of the session (09-03), and a first-class `session_start` branch returning
// `computeToolsToCheck` is filed as a Phase 7 API follow-up.
//
// **The blank `tool_name` is a safety property, not a formality.** Reaching `handleCommandPolicy`
// requires the Path-2 gate (`:846-861`), which needs a non-blank command or a native-tool
// `file_path`. A heartbeat shaped as `tool_name: 'ls'` + `metadata.file_path: cwd` WOULD return
// `tools_to_check` — and would also be evaluated as a real `ls`, which on a `REQUIRE_SLACK_APPROVAL`
// policy fires an approval notification for a command nobody ran (`:2244-2258`, T-09-20). That is why
// nothing here is ever filled in.
//
// **The gate exists because `session_start` is not once per process.** It fires on `/new`, `/resume`,
// `/fork`, `/clone` and `/reload` (`agent-session-runtime.js:141,165,211,229,246,291`), so a developer
// cycling `/new` five times sends five heartbeats against an ungated implementation (T-09-23).

import { APP_LABEL, EVENT_NAME_SESSION_START, TURNLOG_MODEL } from "./constants.ts";
import type { AccountIdentity } from "./accountIdentity.ts";
import { withAccountIdentity } from "./payload.ts";
import type { PretoolRequestBody } from "./types.ts";

export interface HeartbeatInput {
  cwd: string;
  sessionId: string;
  /** `ctx.model` is `Model | undefined`, and at session start it is essentially always undefined. */
  model: string | undefined;
  clientEntrypoint: string;
  hasUI: boolean;
  piVersion: string;
  /** The account pi is signed in as, when the session_start lookup produced one. */
  accountIdentity?: AccountIdentity;
}

export interface HeartbeatGate {
  /**
   * @param fetchedAt the last time policy metadata was learned, or `undefined` for a cold process.
   */
  shouldSend(fetchedAt: number | undefined): boolean;
  markSent(): void;
}

export interface HeartbeatGateOptions {
  now: () => number;
  ttlMs: number;
}

/**
 * The pretool body for a heartbeat. Pure, like the other payload builders.
 *
 * `model` is `TURNLOG_MODEL` for the same reason the turn log pins it: nothing useful is known at
 * session start, and the wire field is required. Note that this is a pretool request, where the model
 * is not row-gating — but sending the same honest placeholder from both paths beats two conventions.
 */
export function buildHeartbeatPayload(input: HeartbeatInput): PretoolRequestBody {
  const body: PretoolRequestBody = {
    conversation_id: input.sessionId,
    model: input.model !== undefined && input.model.length > 0 ? input.model : TURNLOG_MODEL,
    event_name: EVENT_NAME_SESSION_START,
    // Blank tool name, blank command, no `file_path`. See the header: this is what keeps the request
    // out of the command-policy evaluator.
    pre_tool_use_data: {
      tool_name: "",
      command: "",
      metadata: { cwd: input.cwd, has_ui: input.hasUI, pi_version: input.piVersion },
    },
    // Empty rather than absent: the field is required by the server type, and a heartbeat has no
    // prompt to report. Sending a blank prompt through the guardrail path is exactly what §C2 warns
    // against, which is why `event_name` above is not `user_prompt`.
    messages: [],
    unbound_app_label: APP_LABEL,
    client_entrypoint: input.clientEntrypoint,
    // Harmless here (the fall-through attaches no payload) and future-proof if the API later answers
    // this shape with one — at which point `recordSuccess` already handles the fields correctly.
    pull_policies: true,
    first_approval_check: true,
  };
  return withAccountIdentity(body, input.accountIdentity);
}

/**
 * "Once per process, plus once after the warm-up has aged past the TTL."
 *
 * A value rather than a module singleton so a test can build a fresh one; the process-wide instance
 * lives in `index.ts`. Both flags reset on `/reload`, because pi clears the extension module cache
 * (§A7) — one extra heartbeat per reload is acceptable and is the same trade-off the no-key notice
 * already makes.
 */
export function createHeartbeatGate(opts: HeartbeatGateOptions): HeartbeatGate {
  let lastSentAt: number | undefined;

  return {
    shouldSend(fetchedAt: number | undefined): boolean {
      try {
        if (lastSentAt === undefined) return true;
        // Already announced this process. The only thing worth another round trip is a warm-up that
        // has gone stale — and an unknown `fetched_at` is not evidence of staleness, because this
        // process has demonstrably already sent one.
        if (fetchedAt === undefined || !Number.isFinite(fetchedAt)) return false;
        const now = opts.now();
        if (now - fetchedAt <= opts.ttlMs) return false;
        // **Both clocks, not just the warm-up's.** A heartbeat that failed leaves `fetched_at`
        // untouched, so gating on it alone would let every subsequent `/new` through for as long as
        // the gateway stayed down — the storm this gate exists to prevent (T-09-23), with the worst
        // possible trigger. One send per TTL window is the invariant, whatever the response was.
        return now - lastSentAt > opts.ttlMs;
      } catch {
        // A clock that throws must not produce a heartbeat storm.
        return false;
      }
    },

    markSent(): void {
      try {
        lastSentAt = opts.now();
      } catch {
        // A send we cannot timestamp is still a send. `0` would read as "sent long ago" and re-open
        // the gate on the next transition, so an unstampable send is treated as permanently recent:
        // on a clock fault the gate closes rather than storms.
        lastSentAt = Number.MAX_SAFE_INTEGER;
      }
    },
  };
}
