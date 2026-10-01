// WR-03: policy memory and the revoked-key latch scoped by (normalised gateway URL, key fingerprint).
//
// The property under test is isolation: two scopes with different keys, or different gateways, never
// share a tool list, a failure action or a revoked-key latch. Checked both on the state objects and
// end to end, through a real `createPolicyChecker` and `evaluateToolCall` per scope.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { keyFingerprint } from "../src/cache.ts";
import type { ApiClient, PretoolResult } from "../src/client.ts";
import { MAX_TRACKED_SCOPES } from "../src/constants.ts";
import { evaluateToolCall } from "../src/evaluate.ts";
import type { ToolCallInput } from "../src/evaluate.ts";
import { createPolicyChecker } from "../src/policy.ts";
import { createScopedStates, scopeKey } from "../src/scopedState.ts";
import type { ScopedState } from "../src/scopedState.ts";
import { createTelemetry } from "../src/telemetry.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

const NOW = 1_700_000_000_000;
const GATEWAY_A = "https://a.example.com";
const GATEWAY_B = "https://b.example.com";
const KEY_A = ["unb", "scope", "key", "aaaaaaaa"].join("_");
const KEY_B = ["unb", "scope", "key", "bbbbbbbb"].join("_");

// --- The scope key -----------------------------------------------------------------------------

test("scopeKey is the normalised gateway URL plus the key's fingerprint, never the key", () => {
  const key = scopeKey(`${GATEWAY_A}/`, KEY_A);
  assert.equal(key, `${GATEWAY_A} ${keyFingerprint(KEY_A)}`);
  assert.ok(key !== undefined && !key.includes(KEY_A), "the raw key must not appear in the scope key");

  // One gateway spelled two ways is one scope.
  assert.equal(scopeKey("https://A.example.com///", KEY_A), key);
  // A different key or a different gateway is a different scope.
  assert.notEqual(scopeKey(GATEWAY_A, KEY_B), key);
  assert.notEqual(scopeKey(GATEWAY_B, KEY_A), key);
});

test("scopeKey refuses an unusable gateway or key", () => {
  for (const [url, apiKey] of [
    ["http://evil.example.com", KEY_A], // not https and not loopback
    ["https://user:pw@a.example.com", KEY_A],
    ["not a url", KEY_A],
    [undefined, KEY_A],
    [GATEWAY_A, ""],
    [GATEWAY_A, "   "],
    [GATEWAY_A, undefined],
    [GATEWAY_A, 42],
  ] as [unknown, unknown][]) {
    assert.equal(scopeKey(url, apiKey), undefined, `${String(url)} / ${String(apiKey)}`);
  }
});

// --- Isolation on the state objects ------------------------------------------------------------

function learn(state: ScopedState, tools: string[], failureAction: "allow" | "block"): void {
  state.policy.recordSuccess(
    { decision: "allow", tools_to_check: tools, policy_check_failure_action: failureAction },
    NOW,
  );
}

test("two keys on one gateway share no tool list, failure action or revoked latch", () => {
  const scopes = createScopedStates();
  const a = scopes.forScope(GATEWAY_A, KEY_A);
  const b = scopes.forScope(GATEWAY_A, KEY_B);
  assert.notEqual(a, b);
  assert.notEqual(a.policy, b.policy);
  assert.notEqual(a.key, b.key);

  learn(a, [], "block");
  assert.deepEqual(a.policy.getToolsToCheck(), []);
  assert.equal(a.policy.getToolsConfirmed(), true);
  assert.equal(b.policy.getToolsToCheck(), undefined, "B never learned A's tool list");
  assert.equal(b.policy.getToolsConfirmed(), false);
  assert.equal(b.policy.getFailureAction(), undefined, "B never learned A's failure action");

  a.key.recordFailure("HttpStatus401");
  assert.equal(a.key.recordFailure("HttpStatus401"), "inactive");
  assert.equal(a.key.isInactive(), true);
  assert.equal(b.key.isInactive(), false, "A's revoked key does not latch B");

  // And the registry answers the same instances back for the same scope.
  assert.equal(scopes.forScope(`${GATEWAY_A}/`, KEY_A), a);
  assert.equal(scopes.forScope(GATEWAY_A, KEY_B), b);
});

test("one key on two gateways shares no tool list, failure action or revoked latch", () => {
  const scopes = createScopedStates();
  const a = scopes.forScope(GATEWAY_A, KEY_A);
  const b = scopes.forScope(GATEWAY_B, KEY_A);
  assert.notEqual(a, b);

  learn(b, ["read"], "allow");
  assert.equal(a.policy.getToolsToCheck(), undefined);
  assert.equal(a.policy.getFailureAction(), undefined);

  b.key.recordFailure("HttpStatus403");
  b.key.recordFailure("HttpStatus403");
  assert.equal(b.key.isInactive(), true);
  assert.equal(a.key.isInactive(), false);
});

test("the registry never stores the raw key, and keys() lists only fingerprints", () => {
  const scopes = createScopedStates();
  scopes.forScope(GATEWAY_A, KEY_A);
  scopes.forScope(GATEWAY_B, KEY_B);
  const listed = JSON.stringify(scopes.keys());
  assert.equal(listed.includes(KEY_A), false);
  assert.equal(listed.includes(KEY_B), false);
  assert.deepEqual(scopes.keys(), [
    `${GATEWAY_A} ${keyFingerprint(KEY_A)}`,
    `${GATEWAY_B} ${keyFingerprint(KEY_B)}`,
  ]);
});

test("an unusable scope gets a fresh, unstored state on every call", () => {
  const scopes = createScopedStates();
  const first = scopes.forScope("http://evil.example.com", KEY_A);
  learn(first, [], "block");
  first.key.recordFailure("HttpStatus401");
  first.key.recordFailure("HttpStatus401");

  const second = scopes.forScope("http://evil.example.com", KEY_A);
  assert.notEqual(second, first);
  assert.equal(second.policy.getToolsConfirmed(), false, "nothing learned through an unusable scope is shared");
  assert.equal(second.key.isInactive(), false);
  assert.equal(scopes.forScope(GATEWAY_A, "").policy.getToolsToCheck(), undefined);
  assert.equal(scopes.size(), 0);
});

test("the registry is LRU-bounded, defaulting to MAX_TRACKED_SCOPES, with release and clear", () => {
  assert.equal(MAX_TRACKED_SCOPES, 16);
  const scopes = createScopedStates();
  for (let i = 0; i < MAX_TRACKED_SCOPES + 3; i += 1) scopes.forScope(GATEWAY_A, `key-${i}`);
  assert.equal(scopes.size(), MAX_TRACKED_SCOPES);
  assert.equal(scopes.peek(GATEWAY_A, "key-0"), undefined, "the least-recently-used scope went first");
  assert.ok(scopes.peek(GATEWAY_A, `key-${MAX_TRACKED_SCOPES + 2}`) !== undefined);

  const small = createScopedStates({ max: 2 });
  const a = small.forScope(GATEWAY_A, KEY_A);
  small.forScope(GATEWAY_B, KEY_A);
  small.forScope(GATEWAY_A, KEY_A); // use refreshes recency
  small.forScope(GATEWAY_A, KEY_B); // evicts (B, KEY_A)
  assert.equal(small.peek(GATEWAY_A, KEY_A), a);
  assert.equal(small.peek(GATEWAY_B, KEY_A), undefined);

  small.release(GATEWAY_A, KEY_A);
  assert.equal(small.peek(GATEWAY_A, KEY_A), undefined);
  assert.notEqual(small.forScope(GATEWAY_A, KEY_A), a, "a released scope starts cold");
  small.clear();
  assert.equal(small.size(), 0);
});

test("keyState options reach every scope's latch", () => {
  const scopes = createScopedStates({ keyState: { threshold: 1 } });
  assert.equal(scopes.forScope(GATEWAY_A, KEY_A).key.recordFailure("HttpStatus401"), "inactive");
  assert.equal(scopes.forScope(GATEWAY_A, KEY_B).key.isInactive(), false);
});

test("no method throws, whatever it is handed", () => {
  const scopes = createScopedStates(undefined as never);
  const hostile = new Proxy({}, {
    get() {
      throw new Error("hostile");
    },
  });
  for (const [url, apiKey] of [[hostile, hostile], [null, null], [GATEWAY_A, hostile], [{}, []]] as [unknown, unknown][]) {
    assert.doesNotThrow(() => scopes.forScope(url, apiKey));
    assert.doesNotThrow(() => scopes.peek(url, apiKey));
    assert.doesNotThrow(() => scopes.release(url, apiKey));
  }
  assert.doesNotThrow(() => scopeKey(hostile, hostile));
});

// --- End to end: a checker and evaluate per scope ----------------------------------------------

interface Wire {
  client: ApiClient;
  calls: PretoolRequestBody[];
}

/** A client whose pretool answer is `answer()`. Telemetry and turn-log posts succeed silently. */
function wire(answer: () => PretoolResult): Wire {
  const calls: PretoolRequestBody[] = [];
  return {
    calls,
    client: {
      async postPretool(payload) {
        calls.push(payload);
        return answer();
      },
      postHookErrors: async () => true,
      postTurnLog: async () => true,
    },
  };
}

/** One project's wiring, exactly as the scopedState header prescribes. */
function project(scopes: ReturnType<typeof createScopedStates>, baseUrl: string, apiKey: string, w: Wire) {
  const scope = scopes.forScope(baseUrl, apiKey);
  const checker = createPolicyChecker({
    client: w.client,
    state: scope.policy,
    keyState: scope.key,
    now: () => NOW,
    telemetry: createTelemetry({
      client: w.client,
      apiKey,
      profile: TEST_PROFILE,
      isInactive: () => scope.key.isInactive(),
    }),
  });
  return (call: ToolCallInput) =>
    evaluateToolCall(call, {
      checker,
      profile: TEST_PROFILE,
      entrypoint: "agent/1.2.3",
      state: scope.policy,
      now: () => NOW,
    });
}

function readCall(id: string): ToolCallInput {
  return {
    toolName: "read",
    toolCallId: id,
    command: "",
    toolInput: { path: "/work/project/secrets.env" },
    cwd: "/work/project",
    sessionId: "s",
    model: "m",
  };
}

function bashCall(id: string): ToolCallInput {
  return {
    toolName: "bash",
    toolCallId: id,
    command: "cat secrets.env",
    toolInput: { command: "cat secrets.env" },
    cwd: "/work/project",
    sessionId: "s",
    model: "m",
  };
}

test("end to end: A's empty tool list does not cache-skip B's file tools", async () => {
  const scopes = createScopedStates();
  const wireA = wire(() => ({
    ok: true,
    elapsedMs: 1,
    body: { decision: "allow", tools_to_check: [], policy_check_failure_action: "allow" },
  }));
  const wireB = wire(() => ({ ok: true, elapsedMs: 1, body: { decision: "deny", reason: "B blocks reads" } }));
  const evalA = project(scopes, GATEWAY_A, KEY_A, wireA);
  const evalB = project(scopes, GATEWAY_A, KEY_B, wireB);

  // A learns "no file policies" and then cache-skips its own reads.
  assert.equal((await evalA(readCall("a1"))).kind, "allow");
  assert.deepEqual(await evalA(readCall("a2")), { kind: "skip", why: "cached" });
  assert.equal(wireA.calls.length, 1);

  // B, on the same gateway with another key, is still checked — and denied by its own org.
  assert.deepEqual(await evalB(readCall("b1")), { kind: "deny", reason: "B blocks reads" });
  assert.equal(wireB.calls.length, 1);
  assert.equal(wireB.calls[0]?.pull_policies, true, "B has no confirmed list of its own");
});

test("end to end: A's revoked key does not latch B, and A's fail-closed action does not block B", async () => {
  const scopes = createScopedStates();
  // A: an org that is fail-closed, then whose gateway goes down.
  let aDown = false;
  const wireA = wire(() =>
    aDown
      ? { ok: false, errorClass: "HttpStatus503", elapsedMs: 1 }
      : { ok: true, elapsedMs: 1, body: { decision: "allow", policy_check_failure_action: "block" } },
  );
  // C: a revoked key on gateway B.
  const wireC = wire(() => ({ ok: false, errorClass: "HttpStatus401", elapsedMs: 1 }));
  // D: same gateway as C, a good key; its gateway also fails, but its org is fail-open.
  let dDown = false;
  const wireD = wire(() =>
    dDown
      ? { ok: false, errorClass: "HttpStatus503", elapsedMs: 1 }
      : { ok: true, elapsedMs: 1, body: { decision: "allow" } },
  );

  const evalA = project(scopes, GATEWAY_A, KEY_A, wireA);
  const evalC = project(scopes, GATEWAY_B, KEY_A, wireC);
  const evalD = project(scopes, GATEWAY_B, KEY_B, wireD);

  assert.equal((await evalA(bashCall("a1"))).kind, "allow");
  aDown = true;
  assert.equal((await evalA(bashCall("a2"))).kind, "unavailable", "A is fail-closed");

  await evalC(bashCall("c1"));
  await evalC(bashCall("c2"));
  assert.equal(scopes.forScope(GATEWAY_B, KEY_A).key.isInactive(), true, "C's key is latched");
  const cCalls = wireC.calls.length;
  await evalC(bashCall("c3"));
  assert.equal(wireC.calls.length, cCalls, "a latched scope makes no further requests");

  // D shares C's gateway and A's process, but neither C's latch nor A's failure action.
  assert.equal(scopes.forScope(GATEWAY_B, KEY_B).key.isInactive(), false);
  assert.equal((await evalD(bashCall("d1"))).kind, "allow");
  dDown = true;
  assert.equal((await evalD(bashCall("d2"))).kind, "allow", "D's fail-open org is not made fail-closed by A");
  assert.equal(wireD.calls.length, 2, "D is still sending, not latched by C");
});

// --- No silent fallback to the process singleton -----------------------------------------------

test("evaluate.ts has no default to the process-wide policyState", () => {
  const source = readFileSync(resolve(import.meta.dirname, "..", "src", "evaluate.ts"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(?<!:)\/\/[^\n]*/g, "");
  // The identifier, not the module path `./policyState.ts` (whose factory and type are still used).
  assert.equal(/(?<![/\w])policyState\b(?!\.ts)/.test(code), false, "evaluate.ts must not reference the singleton");
  assert.match(code, /\n {2}state: PolicyState;/, "EvaluateDeps.state is required");
});

test("evaluate without a usable state checks against a fresh one, never a shared singleton", async () => {
  // A caller that ignores the types. Each call gets its own cold state, so a list "learned" by one
  // call cannot cache-skip the next one.
  const w = wire(() => ({
    ok: true,
    elapsedMs: 1,
    body: { decision: "allow", tools_to_check: [], policy_check_failure_action: "allow" },
  }));
  const scopes = createScopedStates();
  const scope = scopes.forScope(GATEWAY_A, KEY_A);
  const checker = createPolicyChecker({
    client: w.client,
    state: scope.policy,
    telemetry: createTelemetry({ client: w.client, apiKey: KEY_A, profile: TEST_PROFILE }),
  });
  for (const state of [undefined, null, 7]) {
    const deps = { checker, profile: TEST_PROFILE, entrypoint: "agent/1.2.3", state, now: () => NOW };
    const result = await evaluateToolCall(readCall(`x-${String(state)}`), deps as never);
    assert.equal(result.kind, "allow");
  }
  assert.equal(w.calls.length, 3, "every call was checked: none was cache-skipped on a shared list");
  assert.ok(w.calls.every((call) => call.pull_policies === true));
});
