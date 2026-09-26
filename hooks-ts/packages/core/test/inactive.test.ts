// WR-01 — the revoked-key inactivity latch.
//
// The failure this closes is the worst silent state the extension can reach. A key that resolves but
// is invalid, revoked or wrong-org makes every pretool call 401 (fail open) **and** every bypass
// self-report 401, because `/v1/hooks/errors` uses the same key (§F9). Result before this: no local
// signal, no remote signal, zero enforcement, indefinitely — while the extension reports itself
// active.
//
// Two precedence rules are asserted here because they are where resilience and enforcement disagree:
//
//   1. **The latch outranks fail-closed.** A rejected key means we have no authority to decide
//      anything, so an inactive session allows even for an org whose last-good
//      `policy_check_failure_action` is `block`. Blocking every tool call on a credential problem
//      would turn it into an outage.
//   2. **The latch outranks the breaker.** It is checked first, before any failure-action read and
//      before any fetch, so an inactive session makes zero requests of any kind.
//
// Exact string equality on the error class, never a substring: a future `HttpStatus4010` must not be
// able to trip a 401 latch (T-09-17).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createApiClient } from "../src/client.ts";
import type { ApiClient, PretoolResult } from "../src/client.ts";
import { ERRORS_PATH, KEY_REJECTED_NOTICE, PRETOOL_PATH } from "../src/constants.ts";
import { createKeyState } from "../src/keyState.ts";
import { createPolicyChecker } from "../src/policy.ts";
import { createPolicyState } from "../src/policyState.ts";
import { createTelemetry } from "../src/telemetry.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import { startMockApi } from "./helpers/mockApi.ts";
import type { MockApi } from "./helpers/mockApi.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;
const FIXED_NOW = 1_700_000_000_000;

function payload(): PretoolRequestBody {
  return {
    conversation_id: "sess-abc-123",
    model: "claude-sonnet-4-6",
    event_name: "tool_use",
    pre_tool_use_data: {
      tool_name: "bash",
      command: "cat /etc/shadow",
      metadata: { tool_input: { command: "cat /etc/shadow" } },
    },
    messages: [],
    unbound_app_label: "pi",
    client_entrypoint: "pi/0.87.1",
  };
}

const pretoolCalls = (api: MockApi) => api.requests.filter((r) => r.path === PRETOOL_PATH);
const errorReports = (api: MockApi) => api.requests.filter((r) => r.path === ERRORS_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

interface Notice {
  message: string;
  level: "info" | "warning" | "error";
}

/**
 * A checker wired exactly as the composition root wires it: one shared `keyState` between the
 * decision path and the reporter. `intervalMs: 0` disables the telemetry rate limiter, so "no report
 * after the latch" is a real assertion rather than an artefact of the 60 s window.
 */
function harness(api: MockApi, opts: { failureAction?: "allow" | "block" } = {}) {
  const wire = createApiClient({
    baseUrl: api.url,
    apiKey: TEST_KEY,
    timeoutMs: TIMEOUT_MS,
    errorsTimeoutMs: TIMEOUT_MS,
  });
  const keyState = createKeyState();
  const state = createPolicyState();
  if (opts.failureAction !== undefined) {
    state.recordSuccess({ decision: "allow", policy_check_failure_action: opts.failureAction });
  }
  const notices: Notice[] = [];
  const checker = createPolicyChecker({
    client: wire,
    state,
    telemetry: createTelemetry({
      client: wire,
      apiKey: TEST_KEY,
      now: () => FIXED_NOW,
      intervalMs: 0,
      isInactive: () => keyState.isInactive(),
    }),
    keyState,
  });
  const hooks = {
    notify(message: string, level: "info" | "warning" | "error") {
      notices.push({ message, level });
    },
  };
  return {
    keyState,
    notices,
    state,
    check: () => checker.checkTool(payload(), "bash", hooks),
  };
}

// --- the latch itself ---------------------------------------------------------------------------

test("WR-01 keyState counts only exact 401/403 labels, and only consecutive ones", () => {
  const first = createKeyState();
  assert.equal(first.isInactive(), false, "a fresh session is active");
  assert.equal(first.recordFailure("HttpStatus401"), undefined, "one rejection is not a verdict");
  assert.equal(first.isInactive(), false);
  assert.equal(first.recordFailure("HttpStatus403"), "inactive", "401 then 403 still latches");
  assert.equal(first.isInactive(), true);

  const second = createKeyState();
  second.recordFailure("HttpStatus403");
  assert.equal(second.recordFailure("HttpStatus401"), "inactive", "and in the other order");

  // A run broken by a success is not a run.
  const third = createKeyState();
  third.recordFailure("HttpStatus401");
  third.recordSuccess();
  assert.equal(third.recordFailure("HttpStatus401"), undefined, "two non-consecutive 401s do not latch");
  assert.equal(third.isInactive(), false);

  // Any other failure class is a transient fault, not a credential problem — and it breaks the run.
  const fourth = createKeyState();
  fourth.recordFailure("HttpStatus401");
  assert.equal(fourth.recordFailure("TimeoutError"), undefined);
  assert.equal(fourth.recordFailure("HttpStatus401"), undefined, "the 401 run restarted");
  assert.equal(fourth.isInactive(), false);
});

test("WR-01 a near-miss label cannot fool the latch (T-09-17)", () => {
  // Substring matching on "HttpStatus401" would make every 4010-series status a credential rejection.
  for (const label of ["HttpStatus4010", "HttpStatus40", "httpstatus401", "HttpStatus4031", ""]) {
    const keyState = createKeyState();
    assert.equal(keyState.recordFailure(label), undefined, label);
    assert.equal(keyState.recordFailure(label), undefined, `${label} twice`);
    assert.equal(keyState.isInactive(), false, `${label} must not deactivate the session`);
  }
});

test("WR-01 the transition is reported exactly once and never reverts", () => {
  const keyState = createKeyState();
  keyState.recordFailure("HttpStatus401");
  assert.equal(keyState.recordFailure("HttpStatus401"), "inactive");
  assert.equal(keyState.recordFailure("HttpStatus401"), undefined, "one notice per session");
  assert.equal(keyState.recordFailure("HttpStatus403"), undefined);

  // It latches for the life of the process. Only a `/reload` — which rebuilds the module — starts
  // clean, and a reload is a deliberate user action.
  keyState.recordSuccess();
  assert.equal(keyState.isInactive(), true, "a latched session is not revived by a stray success");
});

test("WR-01 keyState is total, with no throw and no I/O", () => {
  const source = readFileSync(new URL("../src/keyState.ts", import.meta.url), "utf8");
  assert.equal(/^\s*throw /m.test(source), false, "an exception out of here would be a block");
  assert.equal(source.includes("node:"), false, "pure state, no platform surface");

  const keyState = createKeyState();
  // The label comes off a network result and is typed `string`, but it is data.
  assert.doesNotThrow(() => keyState.recordFailure(undefined as unknown as string));
  assert.doesNotThrow(() => keyState.recordFailure(null as unknown as string));
  assert.equal(keyState.isInactive(), false);
});

// --- through checkTool --------------------------------------------------------------------------

test("WR-01 one 401 does not deactivate anything: the next call still tries", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api);
    assert.deepEqual(await h.check(), { kind: "allow" }, "a 401 fails open like any failure");
    assert.equal(pretoolCalls(api).length, 1);
    assert.equal(h.keyState.isInactive(), false, "one rejection could be a fluke");
    assert.deepEqual(h.notices, [], "and says nothing yet");

    await h.check();
    assert.equal(pretoolCalls(api).length, 2, "the second attempt was made");
  } finally {
    await api.close();
  }
});

test("WR-01 the second consecutive 401 latches: one notice, then total silence", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api);
    await h.check();
    await h.check();

    assert.equal(h.keyState.isInactive(), true);
    assert.equal(h.notices.length, 1, `exactly one notice, got ${JSON.stringify(h.notices)}`);
    assert.deepEqual(h.notices[0], { message: KEY_REJECTED_NOTICE, level: "warning" });
    // Locked verbatim by 09-CONTEXT.md, spelled out so a typo in the constant fails here.
    assert.equal(KEY_REJECTED_NOTICE, "Unbound: API key rejected — enforcement inactive");

    const after = pretoolCalls(api).length;
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(await h.check(), { kind: "allow" }, "an inactive session allows");
    }
    assert.equal(pretoolCalls(api).length, after, "zero further pretool requests");
    assert.equal(h.notices.length, 1, "and no repeat notice");
  } finally {
    await api.close();
  }
});

test("WR-01 the latch silences telemetry too, including the latching failure itself", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api);

    await h.check();
    await sleep(60);
    const afterFirst = errorReports(api).length;
    assert.equal(afterFirst, 1, "the first 401 is a reportable bypass (rate limiter disabled)");

    // The latching failure reports nothing: the endpoint uses the same key and would 401 too.
    await h.check();
    await sleep(60);
    assert.equal(errorReports(api).length, 1, "the latch transition is not reported");

    for (let i = 0; i < 3; i += 1) await h.check();
    await sleep(60);
    assert.equal(errorReports(api).length, 1, "zero /v1/hooks/errors requests after the latch");
  } finally {
    await api.close();
  }
});

test("WR-01 a success between two 401s resets the run", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api);
    await h.check();
    api.setMode("allow");
    await h.check();
    api.setMode("401");
    await h.check();

    assert.equal(h.keyState.isInactive(), false, "two non-consecutive rejections are not a rejection");
    assert.equal(pretoolCalls(api).length, 3, "every call was a real attempt");
    assert.deepEqual(h.notices, []);
  } finally {
    await api.close();
  }
});

test("WR-01 inactive allows even for a block-on-failure org — the latch outranks fail-closed", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api, { failureAction: "block" });
    assert.equal(h.state.getFailureAction(), "block", "this org opted out of fail-open");

    // The first rejection is an ordinary failure, so the org's contract still applies.
    assert.deepEqual(await h.check(), { kind: "unavailable" }, "one 401 still honours block");

    // The second makes it inactive, and an inactive session has no authority to block anything.
    assert.deepEqual(await h.check(), { kind: "allow" }, "the latch allows, never blocks");
    assert.equal(h.keyState.isInactive(), true);

    const after = pretoolCalls(api).length;
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(await h.check(), { kind: "allow" }, "and keeps allowing");
    }
    assert.equal(pretoolCalls(api).length, after, "with zero requests, even for a block org");
  } finally {
    await api.close();
  }
});

test("WR-01 the latch is checked before the breaker, so a latched session makes no probe", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const h = harness(api);
    // Three failures would also open the breaker, but the latch fires on the second and pre-empts
    // everything downstream of it — including any half-open probe a minute later.
    await h.check();
    await h.check();
    const after = pretoolCalls(api).length;
    assert.equal(after, 2, "the latch stopped it at two");

    for (let i = 0; i < 5; i += 1) await h.check();
    assert.equal(pretoolCalls(api).length, after);
  } finally {
    await api.close();
  }
});

test("WR-01 keyState is optional: a checker built without one behaves as in Phase 8", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    const wire = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
    const checker = createPolicyChecker({
      client: wire,
      state: createPolicyState(),
      telemetry: createTelemetry({ client: wire, apiKey: TEST_KEY, now: () => FIXED_NOW }),
    });
    // The internal default still latches — the option exists so the composition root can SHARE one
    // instance with the reporter, not to make the behaviour opt-in.
    assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
    assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
    const after = pretoolCalls(api).length;
    await checker.checkTool(payload(), "bash");
    assert.equal(pretoolCalls(api).length, after, "still inactive after two rejections");
  } finally {
    await api.close();
  }
});

test("WR-01 an inactive session cannot reject: checkTool stays total", async () => {
  const hostile: ApiClient = {
    postPretool: (): Promise<PretoolResult> => {
      throw new Error("injected fault");
    },
    postHookErrors: async () => true,
  };
  const keyState = createKeyState();
  keyState.recordFailure("HttpStatus401");
  keyState.recordFailure("HttpStatus401");
  const checker = createPolicyChecker({
    client: hostile,
    state: createPolicyState(),
    telemetry: createTelemetry({ client: hostile, apiKey: TEST_KEY }),
    keyState,
  });

  let outcome: unknown;
  await assert.doesNotReject(async () => {
    outcome = await checker.checkTool(payload(), "bash");
  }, "an inactive session must not reject");
  assert.deepEqual(outcome, { kind: "allow" }, "and it never reaches the client at all");
});
