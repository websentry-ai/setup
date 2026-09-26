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

import { mapResponseToOutcome } from "./verdict.ts";
import type { PolicyOutcome } from "./verdict.ts";
import type { ApiClient } from "./client.ts";
import type { PolicySnapshot, PolicyState } from "./policyState.ts";
import type { Telemetry } from "./telemetry.ts";
import type { PretoolRequestBody } from "./types.ts";

export interface PolicyChecker {
  checkTool(payload: PretoolRequestBody, toolName: string): Promise<PolicyOutcome>;
}

export interface PolicyCheckerOptions {
  client: ApiClient;
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
  /** Injectable clock, so a TTL test drives 300 s in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export function createPolicyChecker(opts: PolicyCheckerOptions): PolicyChecker {
  async function checkTool(
    payload: PretoolRequestBody,
    toolName: string,
  ): Promise<PolicyOutcome> {
    try {
      const res = await opts.client.postPretool(payload);

      if (res.ok) {
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

      // Fail-open, but never silently: the bypass is the audit trail for an accepted risk
      // (T-08-08). Synchronous and unawaited by contract, so a broken errors endpoint cannot
      // slow down or change this decision.
      opts.telemetry.reportBypass({
        errorClass: res.errorClass,
        toolName,
        elapsedMs: res.elapsedMs,
      });

      // The single exception to fail-open: an org that opted out of it via a previously seen
      // `policy_check_failure_action: 'block'`. With nothing remembered — a cold start — a failure
      // allows, matching the Python hook (RESEARCH Open Question 4, deliberate).
      return opts.state.getFailureAction() === "block" ? { kind: "unavailable" } : { kind: "allow" };
    } catch {
      // Unreachable through `createApiClient`, which never rejects — but an injected or future
      // client could, and this is the last net before pi turns an exception into a block.
      return { kind: "allow" };
    }
  }

  return { checkTool };
}
