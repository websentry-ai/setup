// WR-02 — a consecutive-failure circuit breaker for the policy endpoint.
//
// The problem it solves is not enforcement, it is the developer's experience of fail-open. A gateway
// that DROPs packets rather than refusing them costs `PRETOOL_TIMEOUT_MS` per tool call, forever, and
// pi awaits `prepareToolCall` serially even for a "parallel" batch (§F2) — so a six-tool batch takes
// two minutes while enforcement is off anyway. Fail-open promises the developer keeps working; this
// is what makes that promise true.
//
// Four properties are load-bearing:
//
//   1. **No timers.** Freshness is computed on read from an injected clock, exactly like `cache.ts`.
//      A scheduled callback here would keep a handle alive in a process that is about to exit, and
//      would make a 60 s window untestable without either real waiting or a timer mock. (Both
//      scheduling functions are deliberately left unspelled anywhere in this file, because the test
//      for this property is a grep and a grep cannot tell a comment from a call.)
//   2. **Transitions are reported, not states.** `recordFailure` returns `"opened"` only on the
//      closed-to-open edge and `recordSuccess` returns `"closed"` only on the open-to-closed edge, so
//      the adapter can notify once per outage instead of once per failed call. A failed half-open
//      probe re-arms the window but deliberately does NOT re-announce: the outage never ended, so
//      it is still the same open cycle and the developer has already been told.
//   3. **Half-open is exactly one probe.** The first `shouldSkip()` after the window elapses returns
//      false and marks the probe outstanding; every caller behind it skips until that probe's
//      outcome is recorded. A probe whose outcome is never recorded (an injected client that throws
//      takes `policy.ts`'s outer catch) expires with its own window, so the breaker cannot strand
//      itself in a permanent silent bypass.
//   4. **It is total.** No `throw`, no I/O, no allocation per call. `policy.ts` is reachable from a pi
//      `tool_call` handler and an exception out of one is a *block* (§F1).
//
// Scope, decided in 09-02 and asserted in `failopen.test.ts`: the breaker is consulted **only** when
// the last-good `policy_check_failure_action` is not `block` (§F8). Skipping the call and allowing
// would invert a fail-closed org's contract; skipping and blocking for 60 s would brick its session.
// Those orgs keep paying for real attempts. One breaker instance is built per checker, i.e. per
// resolved base URL, so a `UNBOUND_GATEWAY_URL` change starts clean.

import { BREAKER_FAILURE_THRESHOLD, BREAKER_OPEN_MS } from "./constants.ts";

export type BreakerState = "closed" | "open" | "half-open";

export interface Breaker {
  /** True when this call must not touch the network. Marks a half-open probe as outstanding. */
  shouldSkip(): boolean;
  /** `"opened"` on the closed-to-open edge only. */
  recordFailure(): "opened" | undefined;
  /** `"closed"` on the open-to-closed edge only. */
  recordSuccess(): "closed" | undefined;
  state(): BreakerState;
}

export interface BreakerOptions {
  /** Consecutive failures that open the breaker. Defaults to `BREAKER_FAILURE_THRESHOLD`. */
  threshold?: number;
  /** How long the breaker stays open before a single probe is permitted. */
  openMs?: number;
  /** Injected clock, so a 60 s window is testable in microseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export function createBreaker(opts: BreakerOptions = {}): Breaker {
  const now = opts.now ?? Date.now;
  // A non-positive threshold would open the breaker before any failure at all, which is a permanent
  // bypass; a non-positive window would make "open" unobservable. Both fall back to the constants.
  const threshold =
    typeof opts.threshold === "number" && opts.threshold > 0 ? opts.threshold : BREAKER_FAILURE_THRESHOLD;
  const openMs = typeof opts.openMs === "number" && opts.openMs > 0 ? opts.openMs : BREAKER_OPEN_MS;

  let consecutiveFailures = 0;
  /** `undefined` means closed. Otherwise the instant the current open window started. */
  let openedAtMs: number | undefined;
  /** The instant a half-open probe was permitted, or `undefined` when none is outstanding. */
  let probeStartedAtMs: number | undefined;

  function phase(): BreakerState {
    if (openedAtMs === undefined) return "closed";
    // The boundary belongs to the open window: at exactly `openMs` it is still open.
    return now() - openedAtMs > openMs ? "half-open" : "open";
  }

  return {
    shouldSkip(): boolean {
      const current = phase();
      if (current === "closed") return false;
      if (current === "open") return true;

      // Half-open. One probe at a time, and an outstanding probe only holds the line for one window
      // so a lost outcome cannot silence the gateway forever.
      if (probeStartedAtMs !== undefined && now() - probeStartedAtMs <= openMs) return true;
      probeStartedAtMs = now();
      return false;
    },

    recordFailure(): "opened" | undefined {
      probeStartedAtMs = undefined;
      consecutiveFailures += 1;
      if (consecutiveFailures < threshold) return undefined;

      const wasOpen = openedAtMs !== undefined;
      // Re-arm from this failure, so a failed probe buys another full window.
      openedAtMs = now();
      return wasOpen ? undefined : "opened";
    },

    recordSuccess(): "closed" | undefined {
      const wasOpen = openedAtMs !== undefined;
      consecutiveFailures = 0;
      openedAtMs = undefined;
      probeStartedAtMs = undefined;
      return wasOpen ? "closed" : undefined;
    },

    state: phase,
  };
}
