// `checkTool()` — the one function the pi adapter calls, and the last place a failure can be
// contained before it becomes an enforcement decision.
//
// Two invariants, both of which this module exists to hold:
//
//   1. **It cannot throw.** Not "should not": pi's `emitToolCall` has no try/catch, so agent-core
//      converts an exception from a handler into a *block* whose message is handed to the model
//      (§F1). A crash here would therefore both break the developer's tool call and leak the
//      exception text. The entire body sits in one try/catch that returns allow.
//   2. **It cannot return anything but the four outcomes.** Every branch below ends in a
//      `PolicyOutcome`; there is no undefined path, no rethrow, and no `null`.
//
// The precedence inside `checkTool`, in order, because this is where resilience and enforcement
// disagree and every adapter depends on the answer:
//
//   1. **Revoked key** (WR-01) — an inactive session allows with zero HTTP, even for a fail-closed
//      org. A rejected credential gives us no authority to decide anything.
//   2. **Breaker** (WR-02) — an open breaker allows with zero HTTP, but only for a fail-OPEN org; a
//      `block` org is exempt from the mechanism entirely (§F8).
//   3. **The request.** A success clears both runs and may close the breaker (one notice).
//   4. **The latch transition** — the second consecutive 401/403 notifies once, allows, and reports
//      nothing.
//   5. **Decide, then report** (WR-03) — the failure action is read before `reportBypass`, so a
//      fail-closed block is filed as a block and not as a bypass.
//
// Pure composition on purpose: no pi import, no HTTP, no filesystem. That is what makes the
// "client stubbed to raise synchronously" test possible, and it is what will let a future opencode
// adapter reuse this file untouched.
//
// RES-03's on-disk cache does NOT live here either, and that is the point of `onSync`: this module
// hands the recorded snapshot to an injected callback and the composition root
// (`packages/pi/src/index.ts`) decides that the callback writes a file. Importing `cache.ts` here
// would put a filesystem dependency on the reusable decision path for the sake of one call.
// (Spelled that way on purpose: the test for this property is a grep of this file for the node
// filesystem module specifier, and a grep cannot tell a comment from an import.)
//
// Deliberately NOT here: response caching and `tools_to_check` filtering — the skip decision happens
// before a payload is even built, in the adapter (09-03). pi awaits `prepareToolCall` serially even
// for a parallel tool batch (§F2), so each call that gets here is one round trip.

import { createBreaker } from "./breaker.ts";
import type { Breaker } from "./breaker.ts";
import { BREAKER_CLOSED_NOTICE, BREAKER_OPEN_NOTICE, KEY_REJECTED_NOTICE } from "./constants.ts";
import { createKeyState } from "./keyState.ts";
import type { KeyState } from "./keyState.ts";
import { mapResponseToOutcome } from "./verdict.ts";
import type { PolicyOutcome } from "./verdict.ts";
import type { ApiClient } from "./client.ts";
import type { PolicySnapshot, PolicyState } from "./policyState.ts";
import type { Telemetry } from "./telemetry.ts";
import type { PretoolRequestBody } from "./types.ts";

/**
 * The per-call channel back to the live editor session.
 *
 * It is a parameter rather than a constructor option because the checker is built once per process in
 * the adapter's `init()`, while `ctx` — the only thing that can render a notice — arrives with each
 * event. Optional everywhere, and every call site swallows its failures: a notice is cosmetic and
 * must never be able to change a verdict (or, worse, become a thrown handler, which pi reads as a
 * block).
 */
export interface CheckHooks {
  notify?(message: string, level: "info" | "warning" | "error"): void;
}

export interface PolicyChecker {
  checkTool(
    payload: PretoolRequestBody,
    toolName: string,
    hooks?: CheckHooks,
  ): Promise<PolicyOutcome>;
}

export interface PolicyCheckerOptions {
  /**
   * Narrowed to the one method the decision path calls, matching `TelemetryOptions.client`.
   *
   * The checker has no business with the turn log or the error endpoint — those have their own
   * postures and their own call sites — and asking for the whole `ApiClient` would mean every new
   * endpoint invalidated every test double of a module that never uses it.
   */
  client: Pick<ApiClient, "postPretool">;
  state: PolicyState;
  telemetry: Telemetry;
  /**
   * Called with the freshly recorded snapshot after every **successful** response, so a caller can
   * persist it (RES-03). Optional: without it the checker behaves exactly as it did in Phase 8.
   *
   * It runs inside its own try/catch. The real implementation touches a filesystem and can therefore
   * fail (EACCES, ENOSPC), and pi turns an exception out of a `tool_call` handler into a block — so a
   * failed cache write must be invisible to the verdict.
   */
  onSync?: (snapshot: PolicySnapshot) => void;
  /**
   * WR-02's consecutive-failure breaker (`breaker.ts`). **Optional with an internally constructed
   * default**, deliberately: five call sites already build a checker, three of them in Phase 8 test
   * files this wave does not open, and a required field would fail `npm run typecheck`. Because the
   * composition root builds one checker per resolved base URL, the default is already per-base-URL.
   */
  breaker?: Breaker;
  /**
   * WR-01's revoked-key latch (`keyState.ts`). Optional with an internal default for the same reason
   * as `breaker`; the composition root passes one explicitly so the **same** instance is shared with
   * the telemetry reporter, which is the only way "no further HTTP" can include `/v1/hooks/errors`.
   */
  keyState?: KeyState;
  /** Injectable clock, so a TTL test drives 300 s in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

/** A notice must never change a verdict, so every emission is swallowed. */
function notify(hooks: CheckHooks | undefined, message: string, level: "info" | "warning"): void {
  try {
    hooks?.notify?.(message, level);
  } catch {
    // The TUI is not worth a tool call.
  }
}

export function createPolicyChecker(opts: PolicyCheckerOptions): PolicyChecker {
  // One breaker and one latch per checker, built once — per-call instances would never accumulate a
  // failure run, which is the only thing either of them measures.
  const breaker = opts.breaker ?? createBreaker({ now: opts.now });
  const keyState = opts.keyState ?? createKeyState();

  async function checkTool(
    payload: PretoolRequestBody,
    toolName: string,
    hooks?: CheckHooks,
  ): Promise<PolicyOutcome> {
    try {
      // 1. A rejected key first, before anything else. We have no authority to decide, and the
      //    endpoint would only 401 again — so no request, no report, and never a block (WR-01).
      if (keyState.isInactive()) return { kind: "allow" };

      // Read once, before the call, and use the same answer for both breaker decisions: an org that
      // opted out of fail-open is exempt from the breaker entirely (§F8). Skipping its request and
      // allowing would invert the contract it paid for, and skipping-and-blocking for 60 s would
      // brick the session — so it keeps getting real attempts, and a real `unavailable`.
      const breakerApplies = opts.state.getFailureAction() !== "block";

      // 2. Before any fetch: an open breaker means no HTTP and no telemetry — the bypass was already
      //    reported, and notified, when it opened.
      if (breakerApplies && breaker.shouldSkip()) return { kind: "allow" };

      const res = await opts.client.postPretool(payload);

      if (res.ok) {
        // 3. A success ends both runs: the key works and the gateway answers.
        keyState.recordSuccess();
        if (breakerApplies) {
          const closed = breaker.recordSuccess();
          if (closed !== undefined) notify(hooks, BREAKER_CLOSED_NOTICE, "info");
        }
        // Remember the metadata riding this response before interpreting the decision (§B4).
        opts.state.recordSuccess(res.body, (opts.now ?? Date.now)());
        if (opts.onSync !== undefined) {
          try {
            opts.onSync(opts.state.snapshot());
          } catch {
            // A cache that could not be written costs one round trip next session. It must never
            // cost this tool call its verdict, so the failure is swallowed here and not rethrown.
          }
        }
        return mapResponseToOutcome(res.body);
      }

      if (breakerApplies) {
        const opened = breaker.recordFailure();
        if (opened !== undefined) notify(hooks, BREAKER_OPEN_NOTICE, "warning");
      }

      // 4. A second consecutive rejection ends the session's enforcement. Return allow BEFORE
      //    consulting the failure action — the latch outranks fail-closed, because a credential
      //    problem must not become an outage — and report nothing, since the errors endpoint uses
      //    the same rejected key (§F9).
      const latched = keyState.recordFailure(res.errorClass);
      if (latched !== undefined) {
        notify(hooks, KEY_REJECTED_NOTICE, "warning");
        return { kind: "allow" };
      }

      // 5. Decide FIRST, then report (WR-03). A fail-closed org's call was blocked, not bypassed,
      //    and `message.slice(0,100)` is the Sentry fingerprint — so reporting before deciding filed
      //    every fail-closed block under the "enforcement was silently skipped" alert.
      //
      // The single exception to fail-open: an org that opted out of it via a previously seen
      // `policy_check_failure_action: 'block'`. With nothing remembered — a cold start — a failure
      // allows, matching the Python hook (RESEARCH Open Question 4, deliberate).
      const blocked = opts.state.getFailureAction() === "block";

      // The bypass is the audit trail for an accepted risk (T-08-08). Synchronous and unawaited by
      // contract, so a broken errors endpoint cannot slow down or change this decision.
      opts.telemetry.reportBypass({
        errorClass: res.errorClass,
        toolName,
        elapsedMs: res.elapsedMs,
        blocked,
      });

      return blocked ? { kind: "unavailable" } : { kind: "allow" };
    } catch {
      // Unreachable through `createApiClient`, which never rejects — but an injected or future
      // client could, and this is the last net before pi turns an exception into a block.
      return { kind: "allow" };
    }
  }

  return { checkTool };
}
