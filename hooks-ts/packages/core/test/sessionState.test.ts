// CORE-04 / ROADMAP Phase 12 SC4 — state for a host that runs many sessions, many project
// directories and possibly several gateways in ONE process.
//
// Each test below is one sentence of the requirement: two interleaved sessions never see each
// other's turn; two directories never share a heartbeat gate or a notice latch; a gateway that is
// down never opens another gateway's breaker; ending a session drops its state; and nothing here
// grows without limit or throws on a key it cannot use.

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import test from "node:test";

import { createBreakerRegistry } from "../src/breakerRegistry.ts";
import {
  BREAKER_FAILURE_THRESHOLD,
  BREAKER_OPEN_MS,
  CACHE_TTL_MS,
  MAX_TRACKED_GATEWAYS,
  MAX_TRACKED_INSTANCES,
  MAX_TRACKED_SESSIONS,
} from "../src/constants.ts";
import { createInstanceStates, createSessionStates, directoryKey } from "../src/sessionState.ts";
// The only pure clock in the repo; it imports nothing (see breaker.test.ts).
import { createFakeClock } from "../../pi/test/helpers/fakeCtx.ts";

const A = "session-a";
const B = "session-b";

function call(id: string, sessionId: string) {
  return { tool_name: "bash", tool_use_id: id, decision: "allow", session_id: sessionId };
}

function result(id: string) {
  return { tool_name: "bash", tool_use_id: id, is_error: false, content_bytes: 3 };
}

// --- sessions ----------------------------------------------------------------------------------

test("two-session interleave: each session's turn holds only its own prompt, calls and results", () => {
  const sessions = createSessionStates();

  sessions.forSession(A).turn.recordPrompt("prompt for A", A, 100);
  sessions.forSession(B).turn.recordToolCall(call("b-1", B), B, 110);
  sessions.forSession(A).turn.recordToolCall(call("a-1", A), A, 120);
  sessions.forSession(B).turn.recordPrompt("prompt for B", B, 130);
  sessions.forSession(A).turn.recordResult(result("a-1"));
  sessions.forSession(B).turn.recordToolCall(call("b-2", B), B, 140);
  sessions.forSession(B).turn.recordResult(result("b-2"));

  assert.equal(sessions.size(), 2);

  const takenA = sessions.forSession(A).turn.take();
  assert.ok(takenA !== undefined);
  assert.equal(takenA.session_id, A);
  assert.equal(takenA.prompt, "prompt for A");
  assert.equal(takenA.started_at, 100);
  assert.deepEqual(takenA.tool_calls.map((entry) => entry.tool_use_id), ["a-1"]);
  assert.deepEqual(takenA.results.map((entry) => entry.tool_use_id), ["a-1"]);

  // Taking A's turn left B's untouched.
  const takenB = sessions.forSession(B).turn.take();
  assert.ok(takenB !== undefined);
  assert.equal(takenB.session_id, B);
  assert.equal(takenB.prompt, "prompt for B");
  assert.equal(takenB.started_at, 110);
  assert.deepEqual(takenB.tool_calls.map((entry) => entry.tool_use_id), ["b-1", "b-2"]);
  assert.deepEqual(takenB.results.map((entry) => entry.tool_use_id), ["b-2"]);

  assert.equal(JSON.stringify(takenA).includes("b-"), false, "nothing of B in A's record");
  assert.equal(JSON.stringify(takenB).includes("a-1"), false, "nothing of A in B's record");
  assert.equal(JSON.stringify(takenB).includes("prompt for A"), false);
});

test("a session's state is the same object on every lookup and names its session", () => {
  const sessions = createSessionStates();
  const state = sessions.forSession(A);

  assert.equal(state.sessionId, A);
  assert.equal(sessions.forSession(A), state);
  assert.notEqual(sessions.forSession(B).turn, state.turn);
});

test("release drops a session's state; a later lookup starts empty and other sessions are unaffected", () => {
  const sessions = createSessionStates();
  const before = sessions.forSession(A);
  before.turn.recordPrompt("unfinished", A, 100);
  sessions.forSession(B).turn.recordPrompt("still here", B, 100);

  sessions.release(A);
  assert.equal(sessions.size(), 1);

  const after = sessions.forSession(A);
  assert.notEqual(after, before);
  assert.equal(after.turn.isEmpty(), true);
  assert.equal(after.turn.take(), undefined, "the released turn is dropped, never handed back for posting");

  assert.equal(sessions.forSession(B).turn.snapshot().prompt, "still here");

  // Releasing a session that is not tracked, or an unusable id, is a no-op.
  sessions.release("never-seen");
  sessions.release("");
  sessions.release(undefined);
  assert.equal(sessions.size(), 2);
});

test("LRU bound: session MAX_TRACKED_SESSIONS + 1 evicts the least-recently-used session", () => {
  assert.equal(MAX_TRACKED_SESSIONS, 256);
  const sessions = createSessionStates();

  for (let i = 0; i < MAX_TRACKED_SESSIONS; i += 1) {
    sessions.forSession(`s-${i}`).turn.recordPrompt(`prompt ${i}`, `s-${i}`, i);
  }
  assert.equal(sessions.size(), MAX_TRACKED_SESSIONS);

  // Use the oldest one, so the second-oldest is now the least recently used.
  assert.equal(sessions.forSession("s-0").turn.snapshot().prompt, "prompt 0");

  sessions.forSession("one-more");
  assert.equal(sessions.size(), MAX_TRACKED_SESSIONS);
  assert.equal(sessions.forSession("s-0").turn.snapshot().prompt, "prompt 0", "recently used: kept");
  assert.equal(sessions.forSession("s-2").turn.snapshot().prompt, "prompt 2", "not the oldest: kept");

  // s-1 was evicted: looking it up again finds an empty turn (and evicts the next one in line).
  assert.equal(sessions.forSession("s-1").turn.isEmpty(), true);
  assert.equal(sessions.size(), MAX_TRACKED_SESSIONS);
});

test("a custom session cap is honoured", () => {
  const sessions = createSessionStates({ max: 2 });
  sessions.forSession("one").turn.recordPrompt("1", "one", 1);
  sessions.forSession("two");
  sessions.forSession("three");

  assert.equal(sessions.size(), 2);
  assert.equal(sessions.forSession("one").turn.isEmpty(), true);
});

test("invalid session id: an empty or non-string id gets a throwaway state that is never stored", () => {
  const sessions = createSessionStates();
  sessions.forSession(A).turn.recordPrompt("real", A, 100);

  for (const bad of ["", undefined, null, 42, {}, ["x"]]) {
    const throwaway = sessions.forSession(bad);
    assert.equal(throwaway.sessionId, "");
    throwaway.turn.recordPrompt("lost", "", 100);
    throwaway.turn.recordToolCall(call("lost-1", ""), "", 100);

    const next = sessions.forSession(bad);
    assert.notEqual(next, throwaway, "an unusable id must not resolve to shared state");
    assert.equal(next.turn.isEmpty(), true, "what was recorded into the throwaway appears nowhere");
  }

  assert.equal(sessions.size(), 1);
  assert.equal(JSON.stringify(sessions.forSession(A).turn.snapshot()).includes("lost"), false);
});

test("clear drops every session", () => {
  const sessions = createSessionStates();
  sessions.forSession(A).turn.recordPrompt("a", A, 1);
  sessions.forSession(B).turn.recordPrompt("b", B, 1);

  sessions.clear();
  assert.equal(sessions.size(), 0);
  assert.equal(sessions.forSession(A).turn.isEmpty(), true);
});

test("two registries share nothing", () => {
  const one = createSessionStates();
  const two = createSessionStates();
  one.forSession(A).turn.recordPrompt("in one", A, 1);

  assert.equal(two.size(), 0);
  assert.equal(two.forSession(A).turn.isEmpty(), true);
});

// --- instances (directories) -------------------------------------------------------------------

const DIR_A = resolve(sep, "work", "project-a");
const DIR_B = resolve(sep, "work", "project-b");

test("two directories keep independent heartbeat gates and notice latches", () => {
  const clock = createFakeClock();
  const instances = createInstanceStates({ now: clock.now });
  const a = instances.forDirectory(DIR_A);
  const b = instances.forDirectory(DIR_B);

  assert.equal(a.directory, DIR_A);
  assert.equal(b.directory, DIR_B);
  assert.notEqual(a.heartbeatGate, b.heartbeatGate);

  assert.equal(a.heartbeatGate.shouldSend(undefined), true);
  a.heartbeatGate.markSent();
  assert.equal(a.heartbeatGate.shouldSend(undefined), false, "A has announced itself");
  assert.equal(b.heartbeatGate.shouldSend(undefined), true, "A's heartbeat must not silence B's");

  assert.equal(a.noKeyNoticeShown, false);
  a.noKeyNoticeShown = true;
  assert.equal(instances.forDirectory(DIR_A).noKeyNoticeShown, true, "the latch persists for A");
  assert.equal(instances.forDirectory(DIR_B).noKeyNoticeShown, false, "and is not set for B");
  assert.equal(instances.size(), 2);
});

test("the instance heartbeat gate uses the injected clock and the cache TTL", () => {
  const clock = createFakeClock();
  const instances = createInstanceStates({ now: clock.now });
  const gate = instances.forDirectory(DIR_A).heartbeatGate;
  const fetchedAt = clock.now();
  gate.markSent();

  clock.advance(CACHE_TTL_MS);
  assert.equal(gate.shouldSend(fetchedAt), false, "at exactly the TTL the warm-up is still fresh");
  clock.advance(1);
  assert.equal(gate.shouldSend(fetchedAt), true, "past the TTL another heartbeat is due");

  const short = createInstanceStates({ now: clock.now, ttlMs: 10 });
  const shortGate = short.forDirectory(DIR_A).heartbeatGate;
  const at = clock.now();
  shortGate.markSent();
  clock.advance(11);
  assert.equal(shortGate.shouldSend(at), true);
});

test("trailing-slash directory equivalence: one directory, one state, however it is spelled", () => {
  const instances = createInstanceStates();
  const plain = instances.forDirectory(DIR_A);

  assert.equal(instances.forDirectory(DIR_A + sep), plain);
  assert.equal(instances.forDirectory(DIR_A + sep + sep), plain);
  assert.equal(instances.forDirectory(join(DIR_A, "sub", "..")), plain);
  assert.equal(instances.forDirectory(DIR_A + sep + "."), plain);
  assert.equal(instances.size(), 1);

  assert.equal(directoryKey(DIR_A + sep), DIR_A);
  assert.equal(directoryKey(resolve(sep)), resolve(sep), "the root stays the root");
});

test("relative directory refused: a relative, empty or non-string directory is never stored", () => {
  const instances = createInstanceStates();

  for (const bad of ["a", "", ".", "./a", "../a", "work/project-a", undefined, null, 7, {}]) {
    assert.equal(directoryKey(bad), undefined, `directoryKey(${JSON.stringify(bad)})`);

    const throwaway = instances.forDirectory(bad);
    assert.equal(throwaway.directory, "");
    throwaway.noKeyNoticeShown = true;
    throwaway.heartbeatGate.markSent();

    const next = instances.forDirectory(bad);
    assert.notEqual(next, throwaway);
    assert.equal(next.noKeyNoticeShown, false);
    assert.equal(next.heartbeatGate.shouldSend(undefined), true);
  }
  assert.equal(instances.size(), 0);
});

test("instance release and LRU bound at MAX_TRACKED_INSTANCES", () => {
  assert.equal(MAX_TRACKED_INSTANCES, 64);
  const instances = createInstanceStates();
  const first = instances.forDirectory(DIR_A);
  first.noKeyNoticeShown = true;

  instances.release(DIR_A + sep);
  assert.equal(instances.size(), 0);
  assert.equal(instances.forDirectory(DIR_A).noKeyNoticeShown, false, "a released directory starts fresh");

  for (let i = 0; i < MAX_TRACKED_INSTANCES + 10; i += 1) {
    instances.forDirectory(resolve(sep, "work", `p-${i}`));
  }
  assert.equal(instances.size(), MAX_TRACKED_INSTANCES);

  instances.clear();
  assert.equal(instances.size(), 0);
});

// --- breakers (gateway URLs) -------------------------------------------------------------------

const GW_A = "https://gw-a.example";
const GW_B = "https://gw-b.example";

test("per-URL breaker isolation: opening gateway A's breaker leaves gateway B's closed", () => {
  const clock = createFakeClock();
  const breakers = createBreakerRegistry({ now: clock.now });

  assert.equal(breakers.forUrl(GW_A).recordFailure(), undefined);
  assert.equal(breakers.forUrl(GW_A).recordFailure(), undefined);
  assert.equal(breakers.forUrl(GW_A).recordFailure(), "opened");
  assert.equal(BREAKER_FAILURE_THRESHOLD, 3);

  assert.equal(breakers.forUrl(GW_A).state(), "open");
  assert.equal(breakers.forUrl(GW_A).shouldSkip(), true);

  assert.equal(breakers.forUrl(GW_B).state(), "closed");
  assert.equal(breakers.forUrl(GW_B).shouldSkip(), false, "B is still called");
  assert.equal(breakers.size(), 2);

  // The injected clock reaches the breakers: A's window elapses and it permits one probe.
  clock.advance(BREAKER_OPEN_MS + 1);
  assert.equal(breakers.forUrl(GW_A).state(), "half-open");
  assert.equal(breakers.forUrl(GW_A).shouldSkip(), false);
  assert.equal(breakers.forUrl(GW_A).recordSuccess(), "closed");
});

test("trailing-slash URL equivalence: spellings of one gateway share one breaker and one failure count", () => {
  const breakers = createBreakerRegistry();
  const plain = breakers.forUrl(GW_A);

  assert.equal(breakers.forUrl(`${GW_A}/`), plain);
  assert.equal(breakers.forUrl(`${GW_A}//`), plain);
  assert.equal(breakers.forUrl(`  ${GW_A}/?x=1#frag `), plain);
  assert.equal(breakers.forUrl("HTTPS://GW-A.EXAMPLE"), plain);
  assert.equal(breakers.size(), 1);

  // A failure recorded under each spelling counts against the same breaker.
  breakers.forUrl(GW_A).recordFailure();
  breakers.forUrl(`${GW_A}/`).recordFailure();
  assert.equal(breakers.forUrl(`${GW_A}//`).recordFailure(), "opened");

  // A different path is a different gateway.
  assert.notEqual(breakers.forUrl(`${GW_A}/tenant`), plain);
  assert.equal(breakers.forUrl(`${GW_A}/tenant`).state(), "closed");
});

test("invalid URL: an unusable gateway URL gets an unstored breaker and never throws", () => {
  const breakers = createBreakerRegistry();

  for (const bad of ["", "not a url", "http://gw-a.example", "ftp://gw-a.example", "https://user:pw@gw-a.example", undefined, null, 5, {}]) {
    const throwaway = breakers.forUrl(bad);
    assert.equal(throwaway.state(), "closed");
    throwaway.recordFailure();
    throwaway.recordFailure();
    throwaway.recordFailure();

    const next = breakers.forUrl(bad);
    assert.notEqual(next, throwaway);
    assert.equal(next.shouldSkip(), false, "failures on a throwaway breaker open nothing");
  }
  assert.equal(breakers.size(), 0);

  // Loopback http is a usable gateway (the mock), exactly as in `normalizeGatewayUrl`.
  assert.equal(breakers.forUrl("http://127.0.0.1:8799"), breakers.forUrl("http://127.0.0.1:8799/"));
  assert.equal(breakers.size(), 1);
});

test("breaker options reach the breakers, and the registry is bounded at MAX_TRACKED_GATEWAYS", () => {
  assert.equal(MAX_TRACKED_GATEWAYS, 16);

  const strict = createBreakerRegistry({ threshold: 1 });
  assert.equal(strict.forUrl(GW_A).recordFailure(), "opened");

  const breakers = createBreakerRegistry();
  for (let i = 0; i < MAX_TRACKED_GATEWAYS + 5; i += 1) breakers.forUrl(`https://gw-${i}.example`);
  assert.equal(breakers.size(), MAX_TRACKED_GATEWAYS);

  breakers.clear();
  assert.equal(breakers.size(), 0);
});

// --- structure ---------------------------------------------------------------------------------

test("no core module creates a registry at module scope", () => {
  // A module-scope registry is shared by every caller in the process - the bleed these containers
  // exist to remove. Each adapter creates and owns its own.
  const srcDir = resolve(import.meta.dirname, "..", "src");
  const moduleScope = /^(export )?(const|let|var) \w+\s*(:[^=]+)?=\s*create(SessionStates|InstanceStates|BreakerRegistry|KeyedState)\b/m;

  for (const file of readdirSync(srcDir).filter((name) => name.endsWith(".ts"))) {
    assert.equal(moduleScope.test(readFileSync(join(srcDir, file), "utf8")), false, file);
  }
});
