// WR-01 — the revoked-key inactivity latch.
//
// A key that resolves but is rejected is the single worst state this extension can be in, because it
// is invisible from both ends. Every pretool call 401s and fails open; every bypass self-report 401s
// too, because `/v1/hooks/errors` authenticates with the **same** key (§F9). So there is no local
// signal, no remote signal and no enforcement — while the extension still reports itself active. And
// anything that can put a string in the pi process's environment produces it: a malicious repo's
// `.envrc` under direnv, a stale exported value after a key rotation, a tampered profile.
//
// The answer is deliberately small: count consecutive rejections, and on the second one go quiet for
// the session with exactly one notice.
//
//   * **Two, not one.** A single 401 can be a deploy blip or a race with a key rotation; going silent
//     on the first would hand any transient server-side rejection a session-long enforcement
//     shutdown.
//   * **Never a block — for an org that has fail-open.** A rejected key means we have no authority to
//     decide anything, so the latch allows. Turning a credential problem into an outage is a worse
//     failure than the bypass it would prevent, and the bypass is already that org's posture.
//   * **But a fail-CLOSED org is not latched at all.** For an org whose last-good
//     `policy_check_failure_action` is `block`, silence IS the outage it is trying to prevent, and it
//     is one anybody who can produce a 401/403 on this path could trigger deliberately — a proxy on
//     loopback, corporate egress, a WAF or CDN in front of the gateway. So `failClosed` makes every
//     rejection at or past the threshold return `"rejected"` and leaves the session ACTIVE: the
//     caller blocks with `KEY_REJECTED_BLOCK_REASON`, keeps making real attempts, and starts
//     enforcing again on the first success, with no `/reload`.
//
//     The flag is a per-call argument rather than construction state because the remembered failure
//     action is read per call: it can only change on a success, and a success resets the run anyway.
//   * **Exact label equality, never a substring** (T-09-17). `client.ts` builds its label as
//     `HttpStatus${status}`, so a substring test for `HttpStatus401` would also match a future
//     `HttpStatus4010`, and a 4010-series status is not a credential rejection.
//   * **Latched, not sticky-until-success.** Once inactive, a stray success cannot revive the session:
//     nothing issues requests any more, so a success would have to come from somewhere unexpected.
//     `/reload` rebuilds the extension module (§A7) and therefore starts clean, which is the intended
//     recovery path after fixing the key.
//
// Total by construction: no `throw`, no platform surface, no allocation per call.

import { KEY_REJECTION_THRESHOLD } from "./constants.ts";

/** The exact `errorClass` labels `client.ts` produces for a rejected credential. */
const REJECTION_LABELS: ReadonlySet<string> = new Set(["HttpStatus401", "HttpStatus403"]);

/**
 * What a recorded failure means to the caller.
 *
 *   * `undefined` — not a credential rejection, or not enough of them yet. Nothing to do.
 *   * `"inactive"` — the latch just engaged. Returned on the **transition only**, so the caller
 *     notifies once per session rather than once per rejected call.
 *   * `"rejected"` — at or past the threshold with `failClosed`. Returned on **every** such call,
 *     because each one has to produce its own block verdict. The session is not latched.
 */
export type KeyRejectionEffect = "inactive" | "rejected" | undefined;

/** Per-call context the latch cannot read for itself — see the header. */
export interface KeyFailureOptions {
  /** `true` when the remembered `policy_check_failure_action` is `block`. Defaults to `false`. */
  failClosed?: boolean;
}

export interface KeyState {
  /**
   * Feed every failure's `errorClass`, plus whether the org is fail-closed *on this call*.
   */
  recordFailure(errorClass: string, opts?: KeyFailureOptions): KeyRejectionEffect;
  /** A success breaks the consecutive run. It does not revive an already-latched session. */
  recordSuccess(): void;
  isInactive(): boolean;
}

export interface KeyStateOptions {
  /** Consecutive rejections that deactivate the session. Defaults to `KEY_REJECTION_THRESHOLD`. */
  threshold?: number;
}

export function createKeyState(opts: KeyStateOptions = {}): KeyState {
  const threshold =
    typeof opts.threshold === "number" && opts.threshold > 0 ? opts.threshold : KEY_REJECTION_THRESHOLD;

  let consecutiveRejections = 0;
  let inactive = false;

  return {
    recordFailure(errorClass: string, opts: KeyFailureOptions = {}): KeyRejectionEffect {
      if (inactive) return undefined;

      // `errorClass` is typed `string` but arrives off a network result, so it is treated as data.
      if (typeof errorClass !== "string" || !REJECTION_LABELS.has(errorClass)) {
        consecutiveRejections = 0;
        return undefined;
      }

      consecutiveRejections += 1;
      if (consecutiveRejections < threshold) return undefined;

      if (opts.failClosed === true) {
        // No latch: the org's contract is that a failure blocks, and a rejection is a failure. The
        // count is clamped so a long outage cannot drift it upward without bound; `recordSuccess`
        // is still what clears it.
        consecutiveRejections = threshold;
        return "rejected";
      }

      inactive = true;
      return "inactive";
    },

    recordSuccess(): void {
      if (inactive) return;
      consecutiveRejections = 0;
    },

    isInactive: () => inactive,
  };
}

/**
 * The process-wide instance, mirroring `policyState`: the latch has to outlive a single tool call to
 * mean anything, and it resets on `/reload` because pi clears the extension module cache (§A7) — so
 * the way a developer recovers after fixing their key is the same way they reload any other config.
 */
export const keyState: KeyState = createKeyState();
