// RES-05 — the `session_start` heartbeat, through the real composition root and a real mock gateway.
//
// Two facts drive every case here.
//
//   1. **`session_start` is not once per process.** It fires on `/new`, `/resume`, `/fork`, `/clone`
//      and `/reload` (`agent-session-runtime.js:141,165,211,229,246,291`), so a developer cycling
//      `/new` five times would send five heartbeats against an ungated implementation (T-09-23). The
//      gate allows one per process, plus one after the cache TTL lapses.
//   2. **No heartbeat shape available today returns `tools_to_check`** (§C2). The `session_start`
//      event name lands on the fall-through at `preToolUseHandler.ts:1008-1012`, which carries no
//      policy payload at all. So the response must warm `policy_check_failure_action` and must NOT
//      stamp tools-freshness — the `toolsOmitted` mock mode is what proves it.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  CACHE_TTL_MS,
  NO_KEY_NOTICE,
  PRETOOL_PATH,
  SESSION_PRESENCE_ROW_ENABLED,
} from "../../core/src/constants.ts";
import { buildHeartbeatPayload, createHeartbeatGate } from "../../core/src/heartbeat.ts";
import { createPolicyState, policyState } from "../../core/src/policyState.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeClock, createFakeCtx, createFakeSessionStartEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx } from "./helpers/fakeCtx.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TURNLOG_PATH = PI_PROFILE.turnLogPath;

const ENTRYPOINT = "pi/0.87.1";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const heartbeats = (api: MockApi) => api.requests.filter((r) => r.path === PRETOOL_PATH);
const presenceRows = (api: MockApi) => api.requests.filter((r) => r.path === TURNLOG_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

interface Fixture {
  handler: AnyHandler;
  ctx: FakeCtx;
  cleanup(): void;
}

/**
 * Build the extension against a throwaway HOME, and return its `session_start` handler.
 *
 * A temp HOME is not optional: the composition root resolves a real cache path from it, and a test
 * that used the developer's own `~/.pi` would read and write their live policy cache.
 */
/** A fresh, cold gate with the real rule and the real TTL — just not the process-wide instance. */
function freshGate(): Deps["heartbeatGate"] {
  return createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS });
}

async function fixture(api: MockApi, overrides: Partial<Deps> = {}): Promise<Fixture> {
  const homeDir = mkdtempSync(join(tmpdir(), "pi-heartbeat-"));
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension({
    env: { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url },
    homeDir,
    entrypoint: ENTRYPOINT,
    // Cold by default so each case states its own starting point; a case that wants the shared
    // process-wide gate asks for it explicitly.
    heartbeatGate: freshGate(),
    ...overrides,
  })(pi as unknown as ExtensionAPI);

  const handler = handlers.get("session_start");
  assert.ok(handler !== undefined, "session_start must be registered");
  return {
    handler,
    ctx: createFakeCtx(),
    cleanup: () => rmSync(homeDir, { recursive: true, force: true }),
  };
}

// --- the payload -------------------------------------------------------------------------------

test("the heartbeat payload carries the locked fields and nothing tool-shaped", () => {
  const payload = buildHeartbeatPayload({
    cwd: "/tmp/project",
    sessionId: "sess-hb",
    model: undefined,
    clientEntrypoint: ENTRYPOINT,
    hasUI: true,
    agentVersion: "0.87.1",
  }, PI_PROFILE);

  assert.equal(payload.event_name, "session_start");
  assert.equal(payload.pull_policies, true);
  assert.equal(payload.first_approval_check, true);
  assert.equal(payload.client_entrypoint, ENTRYPOINT);
  assert.equal(payload.conversation_id, "sess-hb");
  assert.equal(payload.model, "auto", "ctx.model is undefined at session start");
  assert.equal(payload.unbound_app_label, "pi");

  assert.equal(payload.pre_tool_use_data.tool_name, "", "a blank name keeps it out of the Path-2 gate");
  assert.equal(payload.pre_tool_use_data.command, "");
  // Exactly these three keys. The one thing a heartbeat must never look like is a real tool call:
  // a `file_path` here would reach `handleCommandPolicy` and could fire a Slack approval for a
  // command nobody ran (T-09-20), so the assertion is on the whole key set, not on one absence.
  assert.deepEqual([...Object.keys(payload.pre_tool_use_data.metadata)].sort(), [
    "cwd",
    "has_ui",
    "pi_version",
  ]);
  assert.deepEqual(payload.pre_tool_use_data.metadata, {
    cwd: "/tmp/project",
    has_ui: true,
    pi_version: "0.87.1",
  });
  assert.deepEqual(payload.messages, [], "no prompt is invented for a heartbeat");
});

test("the payload reports has_ui false under pi -p", () => {
  const payload = buildHeartbeatPayload({
    cwd: "/tmp/project",
    sessionId: "sess-hb",
    model: undefined,
    clientEntrypoint: ENTRYPOINT,
    hasUI: false,
    agentVersion: "unknown",
  }, PI_PROFILE);
  assert.equal(payload.pre_tool_use_data.metadata["has_ui"], false);
  assert.equal(payload.pre_tool_use_data.metadata["pi_version"], "unknown");
});

// --- the gate ----------------------------------------------------------------------------------

test("the gate allows one send per process, then refuses", () => {
  const clock = createFakeClock();
  const gate = createHeartbeatGate({ now: clock.now, ttlMs: CACHE_TTL_MS });

  assert.equal(gate.shouldSend(undefined), true, "a cold process sends");
  gate.markSent();
  assert.equal(gate.shouldSend(undefined), false, "a second /new sends nothing");
  assert.equal(gate.shouldSend(clock.now()), false, "and a fresh fetched_at does not re-open it");
});

test("the gate re-opens once the fetched_at it was given has aged past the TTL", () => {
  const clock = createFakeClock();
  const gate = createHeartbeatGate({ now: clock.now, ttlMs: CACHE_TTL_MS });
  const fetchedAt = clock.now();

  gate.markSent();
  assert.equal(gate.shouldSend(fetchedAt), false, "still fresh");

  clock.advance(CACHE_TTL_MS + 1);
  assert.equal(gate.shouldSend(fetchedAt), true, "the warm-up is stale, so one more goes out");
  gate.markSent();
  assert.equal(gate.shouldSend(fetchedAt), false, "and only one");
});

test("a gate that has never sent allows a send regardless of the timestamp", () => {
  const clock = createFakeClock();
  const gate = createHeartbeatGate({ now: clock.now, ttlMs: CACHE_TTL_MS });
  assert.equal(gate.shouldSend(clock.now()), true);
});

// --- through the extension ----------------------------------------------------------------------
//
// These run against the module-scope gate in `index.ts`, so the "three events, one heartbeat" case
// must come FIRST in the file: the gate is per process by design and no later test can get it back
// to a cold state.

test("three session_start events in one process produce exactly one heartbeat and one presence row", async () => {
  const api = await startMockApi({ mode: "toolsOmitted" });
  const f = await fixture(api);
  try {
    for (const reason of ["startup", "new", "resume"] as const) {
      const result = await f.handler(createFakeSessionStartEvent(reason), f.ctx);
      assert.strictEqual(result, undefined, "session_start never returns an opinion");
    }
    await sleep(200);

    assert.equal(
      heartbeats(api).length,
      1,
      `one heartbeat per process, got ${heartbeats(api).length} — pi fires this event on every session transition (§F4)`,
    );
    // Written to hold under EITHER value of the one-line switch, which is the property RESEARCH Open
    // Question 1 asked for: dropping the durable row must not need a test edit.
    assert.equal(
      presenceRows(api).length,
      SESSION_PRESENCE_ROW_ENABLED ? 1 : 0,
      `presence rows disagree with SESSION_PRESENCE_ROW_ENABLED=${SESSION_PRESENCE_ROW_ENABLED}`,
    );

    // And the heartbeat that went out is the locked shape, asserted on the captured wire body.
    const captured = heartbeats(api)[0];
    assert.ok(captured !== undefined);
    const body = captured.body as {
      event_name?: string;
      pull_policies?: boolean;
      first_approval_check?: boolean;
      client_entrypoint?: string;
      pre_tool_use_data?: { tool_name?: string; command?: string; metadata?: Record<string, unknown> };
    };
    assert.equal(body.event_name, "session_start");
    assert.equal(body.pull_policies, true);
    assert.equal(body.first_approval_check, true);
    assert.equal(body.client_entrypoint, ENTRYPOINT);
    assert.equal(body.pre_tool_use_data?.tool_name, "", "a blank name stays out of the Path-2 gate");
    assert.equal(body.pre_tool_use_data?.command, "");
    assert.equal(typeof body.pre_tool_use_data?.metadata?.["has_ui"], "boolean");
    assert.equal(typeof body.pre_tool_use_data?.metadata?.["pi_version"], "string");
    assert.equal(captured.headers["authorization"], `Bearer ${TEST_KEY}`);

    // A heartbeat response must not have faked tools-freshness on the shared state (§C2).
    assert.equal(
      policyState.getToolsSyncedAt(),
      undefined,
      "toolsOmitted carried no tools_to_check, so nothing may claim they synced",
    );
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("the default gate is shared across extension instances, so a /reload-free process sends once", async () => {
  // `undefined` means "use the module-scope default" — the production wiring. Two separate
  // `createExtension` calls must still produce one heartbeat between them, because the limit is a
  // property of the process, not of an extension instance.
  const api = await startMockApi({ mode: "toolsOmitted" });
  const first = await fixture(api, { heartbeatGate: undefined });
  const second = await fixture(api, { heartbeatGate: undefined });
  try {
    await first.handler(createFakeSessionStartEvent("startup"), first.ctx);
    await second.handler(createFakeSessionStartEvent("new"), second.ctx);
    await sleep(200);

    assert.equal(
      heartbeats(api).length,
      1,
      `the module-scope gate is not shared: ${heartbeats(api).length} heartbeats`,
    );
  } finally {
    first.cleanup();
    second.cleanup();
    await api.close();
  }
});

// --- the response, and what it must not do ------------------------------------------------------

test("a response without tools_to_check sets the failure action and NOT tools freshness", () => {
  // Driven directly through `policyState`, which is where the rule lives and where a heartbeat
  // response lands. The `toolsOmitted` mock mode is the exact body this asserts against.
  const state = createPolicyState();
  state.recordSuccess({ decision: "allow", policy_check_failure_action: "block" }, 1_000);

  assert.equal(state.getFailureAction(), "block", "the org's fail-open opt-out is warmed");
  assert.equal(
    state.getToolsSyncedAt(),
    undefined,
    "faking tools-freshness here skips every native file tool for 300 s (§C2/C3)",
  );
  assert.equal(state.getToolsToCheck(), undefined);
  assert.equal(state.getFetchedAt(), 1_000, "it was still a fetch");
});

test("a response that does carry tools_to_check is not special-cased away", () => {
  const state = createPolicyState();
  state.recordSuccess({ decision: "allow", tools_to_check: ["read"] }, 2_000);
  assert.equal(state.getToolsSyncedAt(), 2_000);
  assert.deepEqual(state.getToolsToCheck(), ["read"]);
});

// --- failure and the no-key path ----------------------------------------------------------------

test("a failed heartbeat is a no-op: no notice, no block, still undefined", async () => {
  const api = await startMockApi({ mode: "500" });
  const f = await fixture(api);
  try {
    const result = await f.handler(createFakeSessionStartEvent("fork"), f.ctx);
    await sleep(160);

    assert.strictEqual(result, undefined);
    assert.deepEqual(f.ctx.notifyCalls, [], "a cache miss is not news");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a hanging gateway cannot delay session start", async () => {
  const api = await startMockApi({ mode: "hang" });
  const f = await fixture(api);
  try {
    const startedAt = Date.now();
    const result = await f.handler(createFakeSessionStartEvent("resume"), f.ctx);
    const elapsed = Date.now() - startedAt;

    assert.strictEqual(result, undefined);
    assert.ok(elapsed < 200, `session_start took ${elapsed}ms — both sends are fire-and-forget`);
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("the no-key path sends nothing at all and notifies once", async () => {
  const api = await startMockApi();
  const homeDir = mkdtempSync(join(tmpdir(), "pi-heartbeat-nokey-"));
  try {
    const handlers = new Map<string, AnyHandler>();
    const pi = {
      on(event: string, handler: AnyHandler) {
        handlers.set(event, handler);
        return () => {};
      },
    };
    // No key anywhere: no env var, and a HOME with no `~/.unbound/config.json`.
    await createExtension({ env: {}, homeDir, entrypoint: ENTRYPOINT })(pi as unknown as ExtensionAPI);
    const handler = handlers.get("session_start");
    assert.ok(handler !== undefined);

    const ctx = createFakeCtx();
    await handler(createFakeSessionStartEvent("startup"), ctx);
    await handler(createFakeSessionStartEvent("new"), ctx);
    await sleep(120);

    assert.equal(api.requests.length, 0, "RES-06: no key means no requests of any kind");
    const notices = ctx.notifyCalls.filter((n) => n.message === NO_KEY_NOTICE);
    assert.equal(notices.length, 1, "one notice per extension instance, not one per session");
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
    await api.close();
  }
});
