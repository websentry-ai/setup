// RES-03 — the two-timestamp policy memory.
//
// The bug this file exists to pin is upstream's, not a hypothetical. `handleGuardrails` (the
// user_prompt path) deliberately omits `tools_to_check` (`preToolUseHandler.ts:1399-1405`, comment:
// "echoing tools_to_check here would clobber the hook's tool cache"), and the Python hook then
// stamps its single `last_synced` fresh anyway (`unbound.py:258-299`). On a first-ever session the
// cache therefore becomes **fresh with `[]`**, and `unbound.py:3821-3826` skips every native file
// tool for 300 s. Two independent timestamps are the whole fix:
//
//   * `fetched_at`      — any response that carried policy metadata at all
//   * `tools_synced_at` — ONLY a response that literally contained `tools_to_check`
//
// And `[]` must survive as a value: "this org has no file policies" is an answer, "the field was
// absent" is not. Collapsing the two is what makes the upstream bug possible in the first place.

import assert from "node:assert/strict";
import test from "node:test";

import { CACHE_TTL_MS, MAX_TOOLS_TO_CHECK, MAX_TOOL_NAME_CHARS } from "../src/constants.ts";
import { createPolicyState, parseToolsToCheck } from "../src/policyState.ts";
import type { PolicySnapshot } from "../src/policyState.ts";
import type { PreToolResponseBody } from "../src/types.ts";

/** Fixed clock values — every test drives `recordSuccess` explicitly, none reads the wall clock. */
const T1 = 1_700_000_000_000;
const T2 = T1 + 1_000;
const T3 = T2 + 1_000;

function body(extra: Record<string, unknown> = {}): PreToolResponseBody {
  return { decision: "allow", ...extra };
}

test("parseToolsToCheck: presence, not emptiness, is what undefined means", () => {
  // The whole point: `[]` is a value.
  assert.deepEqual(parseToolsToCheck([]), [], "an empty list is 'no file policies'");

  // Absent or wrong-typed ⇒ "no opinion".
  assert.equal(parseToolsToCheck(undefined), undefined);
  assert.equal(parseToolsToCheck("read"), undefined, "a bare string is not a list");
  assert.equal(parseToolsToCheck({}), undefined);
  assert.equal(parseToolsToCheck(null), undefined);
  assert.equal(parseToolsToCheck(42), undefined);

  // A mixed array keeps only the strings rather than rejecting the whole response.
  assert.deepEqual(
    parseToolsToCheck(["read", 1, null, "write", {}, undefined, "grep"]),
    ["read", "write", "grep"],
  );
});

test("recordSuccess: a response carrying tools_to_check sets the list and advances both timestamps", () => {
  const state = createPolicyState();
  assert.equal(state.getToolsToCheck(), undefined, "cold start knows nothing");
  assert.equal(state.getToolsSyncedAt(), undefined);
  assert.equal(state.getFetchedAt(), undefined);

  state.recordSuccess(body({ tools_to_check: ["read"] }), T1);
  assert.deepEqual(state.getToolsToCheck(), ["read"]);
  assert.equal(state.getToolsSyncedAt(), T1);
  assert.equal(state.getFetchedAt(), T1);
});

test("recordSuccess: a response WITHOUT tools_to_check leaves the list and tools_synced_at alone", () => {
  const state = createPolicyState();
  state.recordSuccess(body({ tools_to_check: ["read"] }), T1);

  // This is the `handleGuardrails` / heartbeat shape: failure action, no tools_to_check key.
  state.recordSuccess(body({ policy_check_failure_action: "block" }), T2);

  assert.deepEqual(state.getToolsToCheck(), ["read"], "an absent field does not clobber");
  assert.equal(state.getToolsSyncedAt(), T1, "tools freshness did NOT move — the upstream bug");
  assert.equal(state.getFailureAction(), "block");
  assert.equal(state.getFetchedAt(), T2, "but the response was still a successful fetch");
});

test("recordSuccess: tools_to_check: [] is an answer and advances tools_synced_at", () => {
  const state = createPolicyState();
  state.recordSuccess(body({ tools_to_check: ["read"] }), T1);

  state.recordSuccess(body({ tools_to_check: [] }), T3);
  assert.deepEqual(state.getToolsToCheck(), [], "the org dropped its file policies");
  assert.equal(state.getToolsSyncedAt(), T3);
  assert.equal(state.getFetchedAt(), T3);
});

test("recordSuccess: a response with no policy metadata advances neither timestamp", () => {
  const state = createPolicyState();
  // `preToolUseHandler.ts:1008-1012` — the no_policy fall-through carries nothing.
  state.recordSuccess(body(), T1);
  assert.equal(state.getFetchedAt(), undefined, "nothing was learned, so nothing was fetched");
  assert.equal(state.getToolsSyncedAt(), undefined);
  assert.equal(state.getToolsToCheck(), undefined);
  assert.equal(state.getFailureAction(), undefined);

  // A deny with a reason is still a response with no policy metadata.
  state.recordSuccess({ decision: "deny", reason: "nope" }, T2);
  assert.equal(state.getFetchedAt(), undefined);
});

test("recordSuccess: an out-of-enum failure action leaves the remembered value standing", () => {
  const state = createPolicyState();
  state.recordSuccess(body({ policy_check_failure_action: "block" }), T1);
  assert.equal(state.getFailureAction(), "block");

  state.recordSuccess(body({ policy_check_failure_action: "BLOCK" }), T2);
  assert.equal(state.getFailureAction(), "block", "a wrong case must not erase the opt-out");

  state.recordSuccess(body({ policy_check_failure_action: null }), T3);
  assert.equal(state.getFailureAction(), "block");

  state.recordSuccess(body({ policy_check_failure_action: "allow" }), T3);
  assert.equal(state.getFailureAction(), "allow", "a valid value still wins");
});

test("recordSuccess: the clock argument defaults to Date.now without breaking the old call shape", () => {
  const state = createPolicyState();
  const before = Date.now();
  // Phase 8 call sites pass one argument; the signature only gained an optional parameter.
  state.recordSuccess(body({ tools_to_check: ["read"] }));
  const after = Date.now();
  const synced = state.getToolsSyncedAt();
  assert.ok(synced !== undefined && synced >= before && synced <= after, `synced ${synced}`);
});

test("snapshot round-trips through hydrate on a cold instance", () => {
  const warm = createPolicyState();
  warm.recordSuccess(body({ tools_to_check: ["read", "grep"], policy_check_failure_action: "block" }), T1);
  const snap = warm.snapshot();

  assert.deepEqual(snap, {
    fetched_at: T1,
    tools_synced_at: T1,
    tools_to_check: ["read", "grep"],
    policy_check_failure_action: "block",
  });

  const cold = createPolicyState();
  cold.hydrate(snap);
  assert.deepEqual(cold.getToolsToCheck(), ["read", "grep"]);
  assert.equal(cold.getToolsSyncedAt(), T1);
  assert.equal(cold.getFailureAction(), "block");
  assert.equal(cold.getFetchedAt(), T1);
  assert.deepEqual(cold.snapshot(), snap, "snapshot -> hydrate -> snapshot is identity");
});

test("snapshot round-trips the empty-list case, which is the one that matters", () => {
  const warm = createPolicyState();
  warm.recordSuccess(body({ tools_to_check: [] }), T1);
  const snap = warm.snapshot();
  assert.deepEqual(snap.tools_to_check, []);

  const cold = createPolicyState();
  cold.hydrate(snap);
  assert.deepEqual(cold.getToolsToCheck(), [], "not undefined — the org has no file policies");
  assert.equal(cold.getToolsSyncedAt(), T1);
});

test("snapshot omits what was never learned", () => {
  const state = createPolicyState();
  assert.deepEqual(state.snapshot(), {}, "a cold snapshot is an empty object, not four undefineds");

  state.recordSuccess(body({ policy_check_failure_action: "allow" }), T1);
  assert.deepEqual(state.snapshot(), { fetched_at: T1, policy_check_failure_action: "allow" });
  assert.ok(!("tools_synced_at" in state.snapshot()), "no tools timestamp without a tools value");
});

test("hydrate never downgrades what the network already taught this instance", () => {
  const state = createPolicyState();
  state.recordSuccess(body({ tools_to_check: ["read"], policy_check_failure_action: "block" }), T2);

  // A concurrent pi session wrote an older, emptier cache. In-memory is authoritative.
  state.hydrate({
    fetched_at: T1,
    tools_synced_at: T1,
    tools_to_check: [],
    policy_check_failure_action: "allow",
  });

  assert.deepEqual(state.getToolsToCheck(), ["read"]);
  assert.equal(state.getToolsSyncedAt(), T2);
  assert.equal(state.getFailureAction(), "block", "a disk 'allow' cannot undo a network 'block'");
  assert.equal(state.getFetchedAt(), T2);
});

test("hydrate fills only the half this instance does not know", () => {
  const state = createPolicyState();
  // Learned the failure action from a heartbeat; never saw tools_to_check.
  state.recordSuccess(body({ policy_check_failure_action: "block" }), T2);
  assert.equal(state.getToolsSyncedAt(), undefined);

  state.hydrate({
    fetched_at: T1,
    tools_synced_at: T1,
    tools_to_check: ["write"],
    policy_check_failure_action: "allow",
  });

  assert.deepEqual(state.getToolsToCheck(), ["write"], "the unknown half is filled from disk");
  assert.equal(state.getToolsSyncedAt(), T1);
  assert.equal(state.getFailureAction(), "block", "the known half is untouched");
  assert.equal(state.getFetchedAt(), T2);
});

test("hydrate re-validates every field — the snapshot came off a file another process wrote", () => {
  const junk: unknown[] = [
    undefined,
    null,
    "not an object",
    42,
    [],
    { tools_synced_at: T1, tools_to_check: "read" },
    { tools_synced_at: "yesterday", tools_to_check: ["read"] },
    { tools_synced_at: Number.NaN, tools_to_check: ["read"] },
    { tools_synced_at: -1, tools_to_check: ["read"] },
    { fetched_at: T1, policy_check_failure_action: "BLOCK" },
    { fetched_at: {}, policy_check_failure_action: "block" },
  ];

  for (const value of junk) {
    const state = createPolicyState();
    assert.doesNotThrow(() => state.hydrate(value as PolicySnapshot), `hydrate(${JSON.stringify(value)})`);
    assert.equal(state.getToolsToCheck(), undefined, `tools stayed unknown for ${JSON.stringify(value)}`);
    assert.equal(state.getToolsSyncedAt(), undefined);
  }

  // A tools value without its timestamp is not usable freshness, so it is not accepted either.
  const noStamp = createPolicyState();
  noStamp.hydrate({ tools_to_check: ["read"] } as PolicySnapshot);
  assert.equal(noStamp.getToolsSyncedAt(), undefined);
  assert.equal(noStamp.getToolsToCheck(), undefined, "an unstamped list cannot be aged");

  // A valid failure action with a junk fetched_at still yields the action — the value is what
  // matters there, because `getFailureAction` ignores the TTL entirely (unbound.py:225).
  const actionOnly = createPolicyState();
  actionOnly.hydrate({ fetched_at: "soon" as unknown as number, policy_check_failure_action: "block" });
  assert.equal(actionOnly.getFailureAction(), "block");
  assert.equal(actionOnly.getFetchedAt(), undefined);
});

test("hydrate copies the list rather than aliasing the caller's array", () => {
  const snap: PolicySnapshot = { tools_synced_at: T1, tools_to_check: ["read"] };
  const state = createPolicyState();
  state.hydrate(snap);
  snap.tools_to_check?.push("bash");
  assert.deepEqual(state.getToolsToCheck(), ["read"], "post-hydrate mutation cannot widen the skip set");
});

test("CACHE_TTL_MS is the Python hook's 300 s in milliseconds", () => {
  assert.equal(CACHE_TTL_MS, 300_000, "unbound.py:70 CACHE_TTL_SECONDS = 300");
});

// --- WR-01: the list a response can make us hold, write and rescan is bounded -------------------

test("parseToolsToCheck: an over-cap list is 'not synced', not a truncated list", () => {
  const huge = Array.from({ length: MAX_TOOLS_TO_CHECK + 1 }, (_, i) => `tool_${i}`);
  // Refused WHOLE, deliberately. Truncating would produce a list that is merely wrong, and being
  // wrong by omission here means `shouldSkipFileTool` skips a tool the org does have a policy for.
  assert.equal(parseToolsToCheck(huge), undefined);
  // Exactly at the cap is still a value — this is a cap, not a smaller taxonomy.
  assert.equal(parseToolsToCheck(huge.slice(0, MAX_TOOLS_TO_CHECK))?.length, MAX_TOOLS_TO_CHECK);
});

test("parseToolsToCheck: an over-long entry is dropped, the rest of the list survives", () => {
  const long = "x".repeat(MAX_TOOL_NAME_CHARS + 1);
  // Per-entry damage only ever NARROWS the skip set (more round trips, identical verdicts), so here
  // dropping the bad entry is the safe direction and keeping the response is worth it.
  assert.deepEqual(parseToolsToCheck(["read", long, "write"]), ["read", "write"]);
  assert.deepEqual(parseToolsToCheck(["x".repeat(MAX_TOOL_NAME_CHARS)]), ["x".repeat(MAX_TOOL_NAME_CHARS)]);
});

test("WR-01: an over-cap tools_to_check is not stored and does not stamp tools_synced_at", () => {
  const state = createPolicyState();
  state.recordSuccess(
    {
      decision: "allow",
      tools_to_check: Array.from({ length: MAX_TOOLS_TO_CHECK + 1 }, () => "read"),
      policy_check_failure_action: "block",
    } as PreToolResponseBody,
    T1,
  );
  // Nothing stored, nothing stamped: the state stays at "never learned", which costs a round trip
  // per file tool and enforces on every one of them.
  assert.equal(state.getToolsToCheck(), undefined);
  assert.equal(state.getToolsSyncedAt(), undefined);
  assert.equal(state.snapshot().tools_to_check, undefined);
  // The failure action on the same response is still learned — one bad field must not cost the one
  // field that can turn an API failure into a block.
  assert.equal(state.getFailureAction(), "block");
});

test("WR-01: an over-cap list on DISK is a cache miss for both halves", () => {
  const state = createPolicyState();
  state.hydrate({
    tools_synced_at: T1,
    tools_to_check: Array.from({ length: MAX_TOOLS_TO_CHECK + 1 }, () => "read"),
  });
  // Both or neither: a refused list must not leave its stamp behind, or the stamp alone would look
  // fresh with nothing to check against.
  assert.equal(state.getToolsToCheck(), undefined);
  assert.equal(state.getToolsSyncedAt(), undefined);
});
