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
// Deliberately NOT here: response caching, memoisation, and `tools_to_check` filtering. Those are
// RES-03 in Phase 9; `policyState` already stores the field so Phase 9 only adds the read. pi awaits
// `prepareToolCall` serially even for a parallel tool batch (§F2), so each call is one round trip —
// worth knowing before adding anything to this path.

import { mapResponseToOutcome } from "./verdict.ts";
import type { PolicyOutcome } from "./verdict.ts";
import type { ApiClient } from "./client.ts";
import type { PolicyState } from "./policyState.ts";
import type { Telemetry } from "./telemetry.ts";
import type { PretoolRequestBody } from "./types.ts";

export interface PolicyChecker {
  checkTool(payload: PretoolRequestBody, toolName: string): Promise<PolicyOutcome>;
}

export interface PolicyCheckerOptions {
  client: ApiClient;
  state: PolicyState;
  telemetry: Telemetry;
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
        opts.state.recordSuccess(res.body);
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
