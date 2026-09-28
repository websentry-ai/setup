// RES-03, read side — the zero-HTTP fast path, proved against the mock rather than against a stub.
//
// Every "is skipped" assertion below is `mock.requests.length === 0`. A stubbed checker would let a
// broken predicate pass: the mock models the server's Path-2 entry gate, and it is scripted `deny`
// in most cases here, so a request that *was* made would produce a visible block. Silence is
// therefore evidence.
//
// Three properties are load-bearing and each has its own case:
//
//   * a native file tool **absent** from a tools-fresh `tools_to_check` costs nothing;
//   * `bash`, `powershell` and any non-native name are **never** skippable, whatever the list says —
//     they are evaluated on `command`, which no cached list can answer for;
//   * `pull_policies: true` rides exactly the requests that can fill the cache: the first real tool
//     call and the first one after the tools TTL lapses. Never a fabricated heartbeat call, which
//     the server would evaluate as a genuine tool use and could escalate to a Slack approval for a
//     command nobody ran.
//
// Freshness is driven by an injected clock, never by real time: `createFakeClock` makes "300 s from
// now" a statement rather than a wait, and the whole file still runs in milliseconds.

import assert from "node:assert/strict";
import test from "node:test";

import { areToolsFresh, shouldSkipFileToolFromState } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import { NATIVE_FILE_TOOLS } from "../../core/src/payload.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { decideToolCall } from "../src/decide.ts";
import type { DecideDeps } from "../src/decide.ts";
import { createFakeClock, createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeClock } from "./helpers/fakeCtx.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";

const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";
/** `CACHE_TTL_MS`, spelled out: the 300 s window is the contract, not an implementation detail. */
const TTL_MS = 300_000;

function depsFor(api: MockApi, state: PolicyState, clock: FakeClock): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
  return {
    checker: createPolicyChecker({
      client,
      state,
      telemetry: createTelemetry({ client, apiKey: TEST_KEY }),
      now: clock.now,
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
    state,
    now: clock.now,
  };
}

function pretoolBodies(api: MockApi): Record<string, unknown>[] {
  return api.requests
    .filter((r) => r.path === PRETOOL_PATH)
    .map((r) => r.body as Record<string, unknown>);
}

/**
 * Seed the in-memory state exactly as a successful response would, at `clock`'s current time.
 *
 * Deliberately not via a cache file: the disk path is `cache.test.ts`'s subject, and going through
 * `recordSuccess` is what makes `tools_synced_at` move for the right reason.
 */
function seedTools(state: PolicyState, clock: FakeClock, tools: string[]): void {
  state.recordSuccess({ decision: "allow", policy_check_failure_action: "allow", tools_to_check: tools }, clock.now());
  assert.equal(state.getToolsSyncedAt(), clock.now(), "the seed must have stamped tools_synced_at");
}

interface SkipCase {
  toolName: string;
  input?: Record<string, unknown>;
}

/** Run one call against a scripted mock with a pre-seeded state, and report what crossed the wire. */
async function runSeeded(
  mode: MockMode,
  tools: string[],
  cases: SkipCase[],
  advanceMs = 0,
): Promise<{
  results: (unknown | undefined)[];
  bodies: Record<string, unknown>[];
}> {
  const clock = createFakeClock();
  const state = createPolicyState();
  seedTools(state, clock, tools);
  clock.advance(advanceMs);

  const api = await startMockApi({ mode });
  const ctx = createFakeCtx({ cwd: "/tmp/project-x" });
  const deps = depsFor(api, state, clock);
  try {
    const results: unknown[] = [];
    for (const c of cases) {
      results.push(
        await decideToolCall(createFakeToolCallEvent(c.toolName, c.input ?? { path: "/x/y" }), ctx, deps),
      );
    }
    return { results, bodies: pretoolBodies(api) };
  } finally {
    await api.close();
  }
}

test("RES-03 a file tool absent from a fresh tools_to_check costs zero HTTP requests", async () => {
  // `grep` is not in the list, so nothing server-side could say about it that the list has not
  // already said. A `deny`-scripted mock proves the silence: a request would have blocked.
  const { results, bodies } = await runSeeded("deny", ["read", "write"], [
    { toolName: "grep", input: { pattern: "secret" } },
  ]);

  assert.equal(results[0], undefined, "allowed locally");
  assert.equal(bodies.length, 0, "and without asking");
});

test("RES-03 a file tool present in a fresh tools_to_check still round-trips and is denied", async () => {
  const { results, bodies } = await runSeeded("deny", ["read", "write"], [
    { toolName: "read", input: { path: "/etc/shadow" } },
  ]);

  assert.deepStrictEqual(results[0], {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(bodies.length, 1, "a listed tool is always asked about");
});

test("RES-03 an empty-but-fresh tools_to_check skips every one of the six native file tools", async () => {
  const cases: SkipCase[] = [
    { toolName: "read", input: { path: "/x" } },
    { toolName: "write", input: { path: "/x" } },
    { toolName: "edit", input: { path: "/x" } },
    { toolName: "grep", input: { pattern: "x" } },
    { toolName: "find", input: {} },
    { toolName: "ls", input: {} },
  ];
  assert.equal(cases.length, NATIVE_FILE_TOOLS.size, "the case list must cover the whole taxonomy");

  const { results, bodies } = await runSeeded("deny", [], cases);

  assert.deepStrictEqual(results, [undefined, undefined, undefined, undefined, undefined, undefined]);
  assert.equal(bodies.length, 0, "`[]` means no file policies — six calls, zero round trips");
});

test("RES-03 bash and powershell are never skipped, even with an empty fresh tools_to_check", async () => {
  const { results, bodies } = await runSeeded("deny", [], [
    { toolName: "bash", input: { command: "cat /etc/shadow" } },
    { toolName: "powershell", input: { command: "Get-Content C:\\secrets.txt" } },
  ]);

  for (const result of results) {
    assert.deepStrictEqual(result, {
      block: true,
      reason: "Blocked by Unbound policy: Reading secrets is blocked.",
    });
  }
  assert.equal(bodies.length, 2, "a shell command is never answerable from a cached tool list");
});

test("RES-03 an expired tools TTL forces a round trip that carries pull_policies: true", async () => {
  const { results, bodies } = await runSeeded(
    "deny",
    ["read", "write"],
    [{ toolName: "grep", input: { pattern: "secret" } }],
    TTL_MS + 1,
  );

  assert.deepStrictEqual(results[0], {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(bodies.length, 1, "a stale list is no list at all");
  assert.equal(bodies[0]?.pull_policies, true, "the trip that pays for itself refreshes the list");
});

test("RES-03 pull_policies rides the first real tool call and is absent, not false, while fresh", async () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  const api = await startMockApi({ mode: "toolsList" });
  const ctx = createFakeCtx();
  const deps = depsFor(api, state, clock);
  try {
    await decideToolCall(createFakeToolCallEvent("read", { path: "/a" }), ctx, deps);
    await decideToolCall(createFakeToolCallEvent("read", { path: "/b" }), ctx, deps);

    const bodies = pretoolBodies(api);
    assert.equal(bodies.length, 2, "`read` is in the returned list, so both calls are evaluated");
    assert.equal(bodies[0]?.pull_policies, true, "nothing learned yet ⇒ pull");
    assert.equal(
      Object.hasOwn(bodies[1] ?? {}, "pull_policies"),
      false,
      "absent, not `false` — the wire body stays minimal",
    );
  } finally {
    await api.close();
  }
});

// The predicate itself, at the seam. The integration cases above cannot distinguish "not skipped by
// the file-tool path" from "skipped by the nothing-evaluable guard", because a custom tool with no
// command and no path is silent for the second reason. So the taxonomy edge is asserted directly.

test("RES-03 the skip predicate refuses every name outside the six, whatever the list says", () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  seedTools(state, clock, []);

  for (const toolName of ["bash", "powershell", "mcp__notion__search", "some_custom_tool", "READ", "Read", ""]) {
    assert.equal(
      shouldSkipFileToolFromState(toolName, state, clock.now()),
      false,
      `${toolName} must never be cache-skipped`,
    );
  }
  // And the six are, under the same state.
  for (const toolName of NATIVE_FILE_TOOLS) {
    assert.equal(shouldSkipFileToolFromState(toolName, state, clock.now()), true, toolName);
  }
});

test("RES-03 the skip predicate needs tools-freshness, and the window boundary belongs to fresh", () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  seedTools(state, clock, []);
  const syncedAt = clock.now();

  assert.equal(areToolsFresh(syncedAt, syncedAt + TTL_MS - 1), true);
  assert.equal(areToolsFresh(syncedAt, syncedAt + TTL_MS), true, "exactly 300 000 ms is still fresh");
  assert.equal(areToolsFresh(syncedAt, syncedAt + TTL_MS + 1), false);
  assert.equal(areToolsFresh(undefined, syncedAt), false, "never synced is never fresh");
  assert.equal(areToolsFresh(syncedAt, syncedAt - 1), false, "a future stamp is skew, not freshness");

  assert.equal(shouldSkipFileToolFromState("read", state, syncedAt + TTL_MS), true);
  assert.equal(shouldSkipFileToolFromState("read", state, syncedAt + TTL_MS + 1), false);
});

test("RES-03 a state that never learned a list skips nothing", () => {
  const clock = createFakeClock();
  const state = createPolicyState();

  assert.equal(state.getToolsSyncedAt(), undefined);
  for (const toolName of NATIVE_FILE_TOOLS) {
    assert.equal(shouldSkipFileToolFromState(toolName, state, clock.now()), false, toolName);
  }
});

// --- WR-02: a hydrated list is confirmed once per session before it may suppress anything ---------
//
// The threat these two cases close: a same-UID local process reads `policy_cache.json` — which carries
// both halves of the identity, `gateway_url` and `key_fingerprint`, in cleartext — and rewrites it as
// `{tools_to_check: [], tools_synced_at: now, fetched_at: now}`. Every read/write/edit/grep/find/ls
// for the next 300 s was then allowed with zero HTTP, renewably, because `pullPolicies` was derived
// from the *hydrated* stamp and so the extension declined to ask during exactly the window a planted
// file controlled. Enforcement reported itself active throughout.

test("WR-02 a planted fresh cache cannot suppress the first tool call of a session", async () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  // Exactly what a planted file produces after `readCache`: a fresh stamp and an empty list, arriving
  // through `hydrate` rather than `recordSuccess` — which is the only difference that matters.
  state.hydrate({ tools_to_check: [], tools_synced_at: clock.now(), fetched_at: clock.now() });
  assert.equal(state.getToolsSyncedAt(), clock.now(), "the plant looks perfectly fresh");
  assert.equal(state.getToolsConfirmed(), false, "but no server in this process ever said so");

  // `toolsEmpty` answers `[]` too, so the SERVER agrees there are no file policies. The point is not
  // the answer, it is that we asked at all.
  const api = await startMockApi({ mode: "toolsEmpty" });
  const ctx = createFakeCtx({ cwd: "/tmp/project-x" });
  const deps = depsFor(api, state, clock);
  try {
    const first = await decideToolCall(createFakeToolCallEvent("grep", { pattern: "secret" }), ctx, deps);
    let bodies = pretoolBodies(api);
    assert.equal(bodies.length, 1, "the first file tool of the session round-trips regardless");
    assert.equal(bodies[0]?.pull_policies, true, "and asks for the list it refuses to take on faith");
    assert.equal(first, undefined, "the server's own `[]` allows it");

    // One round trip, then the cache is worth what it was always supposed to be worth.
    assert.equal(state.getToolsConfirmed(), true, "the response confirmed the list");
    const second = await decideToolCall(createFakeToolCallEvent("grep", { pattern: "secret" }), ctx, deps);
    bodies = pretoolBodies(api);
    assert.equal(bodies.length, 1, "the second call skips — the self-heal costs one trip, not every trip");
    assert.equal(second, undefined);
  } finally {
    await api.close();
  }
});

test("WR-02 the confirming round trip still enforces: a planted [] cannot pre-allow a denied tool", async () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  state.hydrate({ tools_to_check: [], tools_synced_at: clock.now(), fetched_at: clock.now() });

  // The attacker's goal, stated as a test: `read` is absent from the planted list, so before WR-02
  // this returned `undefined` with zero HTTP. A `deny`-scripted mock makes the difference visible.
  const api = await startMockApi({ mode: "deny" });
  const ctx = createFakeCtx({ cwd: "/tmp/project-x" });
  const deps = depsFor(api, state, clock);
  try {
    const result = await decideToolCall(createFakeToolCallEvent("read", { path: "/etc/shadow" }), ctx, deps);
    assert.deepStrictEqual(result, {
      block: true,
      reason: "Blocked by Unbound policy: Reading secrets is blocked.",
    });
    assert.equal(pretoolBodies(api).length, 1, "the plant bought the attacker nothing");
  } finally {
    await api.close();
  }
});
