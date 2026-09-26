// WR-02 — the circuit breaker, as a state machine and as it behaves through `checkTool`.
//
// The unit half runs entirely on `createFakeClock`: a breaker whose window is 60 s cannot be tested
// with real timers without either taking a minute or being flaky, and `setTimeout` inside the
// breaker would also leave a handle alive in a pi process that is about to exit. So freshness is
// computed on read, exactly like the policy cache, and every assertion below advances a pure clock.
//
// The integration half lives in `failopen.test.ts`, beside the other `checkTool` failure-matrix
// cases — including the one that matters most: a fail-CLOSED org must never be disarmed by the
// breaker (§F8).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createBreaker } from "../src/breaker.ts";
import { BREAKER_FAILURE_THRESHOLD, BREAKER_OPEN_MS } from "../src/constants.ts";
// The only pure clock in the repo (09-00). It has no imports of its own, so borrowing it here adds
// no dependency from core onto the pi package — only onto a test fixture.
import { createFakeClock } from "../../pi/test/helpers/fakeCtx.ts";

const THRESHOLD = 3;
const OPEN_MS = 60_000;

function breakerWithClock() {
  const clock = createFakeClock();
  const breaker = createBreaker({ threshold: THRESHOLD, openMs: OPEN_MS, now: clock.now });
  return { breaker, clock };
}

/** Fail `n` times in a row, returning every transition label the breaker reported. */
function fail(breaker: ReturnType<typeof createBreaker>, n: number): (string | undefined)[] {
  const seen: (string | undefined)[] = [];
  for (let i = 0; i < n; i += 1) seen.push(breaker.recordFailure());
  return seen;
}

test("WR-02 the defaults are the locked threshold and window", () => {
  assert.equal(BREAKER_FAILURE_THRESHOLD, 3);
  assert.equal(BREAKER_OPEN_MS, 60_000);

  // A breaker built with no options must use them, since that is what `policy.ts` constructs.
  const breaker = createBreaker();
  assert.equal(breaker.state(), "closed");
  fail(breaker, BREAKER_FAILURE_THRESHOLD - 1);
  assert.equal(breaker.shouldSkip(), false, "one short of the threshold still calls the gateway");
  breaker.recordFailure();
  assert.equal(breaker.shouldSkip(), true, "the threshold-th failure opens it");
});

test("WR-02 two failures leave it closed, the third opens it", () => {
  const { breaker } = breakerWithClock();

  assert.equal(breaker.state(), "closed");
  assert.deepEqual(fail(breaker, 2), [undefined, undefined], "no transition below the threshold");
  assert.equal(breaker.shouldSkip(), false, "two failures are not an outage");
  assert.equal(breaker.state(), "closed");

  assert.equal(breaker.recordFailure(), "opened", "the third failure is the transition");
  assert.equal(breaker.state(), "open");
  assert.equal(breaker.shouldSkip(), true);
});

test("WR-02 the open window lasts exactly openMs on the injected clock", () => {
  const { breaker, clock } = breakerWithClock();
  fail(breaker, THRESHOLD);

  clock.advance(OPEN_MS - 1);
  assert.equal(breaker.state(), "open", `still open at ${OPEN_MS - 1}ms`);
  assert.equal(breaker.shouldSkip(), true);

  clock.advance(1); // exactly openMs
  assert.equal(breaker.state(), "open", "the boundary belongs to the open window");
  assert.equal(breaker.shouldSkip(), true);

  clock.advance(1); // openMs + 1
  assert.equal(breaker.state(), "half-open");
});

test("WR-02 the open transition is reported exactly once across four consecutive failures", () => {
  const { breaker } = breakerWithClock();

  // The adapter turns each non-undefined return into one in-editor notice, so a fourth failure
  // inside the same window returning "opened" again would mean a notice per failure.
  const labels = fail(breaker, 4);
  assert.deepEqual(labels, [undefined, undefined, "opened", undefined]);
  assert.equal(labels.filter((l) => l === "opened").length, 1, "exactly one open notice");
});

test("WR-02 half-open permits exactly one probe", () => {
  const { breaker, clock } = breakerWithClock();
  fail(breaker, THRESHOLD);
  clock.advance(OPEN_MS + 1);

  assert.equal(breaker.state(), "half-open");
  assert.equal(breaker.shouldSkip(), false, "the probe is permitted");
  assert.equal(breaker.shouldSkip(), true, "a second caller waits for the probe's outcome");
  assert.equal(breaker.shouldSkip(), true);
});

test("WR-02 a successful probe closes the breaker and resets the failure count", () => {
  const { breaker, clock } = breakerWithClock();
  fail(breaker, THRESHOLD);
  clock.advance(OPEN_MS + 1);
  assert.equal(breaker.shouldSkip(), false);

  assert.equal(breaker.recordSuccess(), "closed", "the close transition is reported once");
  assert.equal(breaker.state(), "closed");
  assert.equal(breaker.shouldSkip(), false);
  assert.equal(breaker.recordSuccess(), undefined, "an already-closed breaker says nothing");

  // The count was reset, so it takes another full threshold to re-open.
  assert.deepEqual(fail(breaker, THRESHOLD - 1), [undefined, undefined]);
  assert.equal(breaker.shouldSkip(), false);
  assert.equal(breaker.recordFailure(), "opened");
});

test("WR-02 a failed probe re-opens for another full window without re-announcing", () => {
  const { breaker, clock } = breakerWithClock();
  fail(breaker, THRESHOLD);
  clock.advance(OPEN_MS + 1);
  assert.equal(breaker.shouldSkip(), false, "the probe goes out");

  // The outage never ended, so this is the same open cycle: no second notice.
  assert.equal(breaker.recordFailure(), undefined, "one notice per outage, not per probe");
  assert.equal(breaker.state(), "open");
  assert.equal(breaker.shouldSkip(), true);

  clock.advance(OPEN_MS);
  assert.equal(breaker.state(), "open", "the window restarted from the failed probe");
  clock.advance(1);
  assert.equal(breaker.state(), "half-open");
  assert.equal(breaker.shouldSkip(), false, "and a fresh probe is permitted");
});

test("WR-02 a probe whose outcome is never recorded cannot strand the breaker", () => {
  // `policy.ts` records an outcome on both branches, but an injected client that throws takes the
  // outer catch, and a permanently-true `shouldSkip` would be a permanent silent bypass.
  const { breaker, clock } = breakerWithClock();
  fail(breaker, THRESHOLD);
  clock.advance(OPEN_MS + 1);
  assert.equal(breaker.shouldSkip(), false, "probe one");
  assert.equal(breaker.shouldSkip(), true, "held while that probe is outstanding");

  clock.advance(OPEN_MS + 1);
  assert.equal(breaker.shouldSkip(), false, "a stranded probe expires with its own window");
});

test("WR-02 a success resets the count even while the breaker is closed", () => {
  const { breaker } = breakerWithClock();
  fail(breaker, THRESHOLD - 1);
  assert.equal(breaker.recordSuccess(), undefined, "no transition: it was never open");
  assert.deepEqual(fail(breaker, THRESHOLD - 1), [undefined, undefined], "the run restarted");
  assert.equal(breaker.shouldSkip(), false, "two non-consecutive failures are not an outage");
});

test("WR-02 breakers are independent instances, so one per base URL shares nothing", () => {
  const clock = createFakeClock();
  const first = createBreaker({ threshold: THRESHOLD, openMs: OPEN_MS, now: clock.now });
  const second = createBreaker({ threshold: THRESHOLD, openMs: OPEN_MS, now: clock.now });

  fail(first, THRESHOLD);
  assert.equal(first.shouldSkip(), true);
  assert.equal(second.shouldSkip(), false, "a second gateway is not implicated by the first's outage");
  assert.equal(second.state(), "closed");
});

test("WR-02 the breaker is timer-free and total", () => {
  const source = readFileSync(new URL("../src/breaker.ts", import.meta.url), "utf8");
  // Spelled in two halves so this assertion cannot match its own source text.
  assert.equal(source.includes("set" + "Timeout"), false, "freshness is computed on read");
  assert.equal(source.includes("set" + "Interval"), false, "no background work in a hook process");
  assert.equal(/^\s*throw /m.test(source), false, "an exception out of here would be a block");
});
