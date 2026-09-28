// RES-03 on the heartbeat path — the `session_start` response reaches the DISK, not just memory.
//
// `policy_check_failure_action` is the one field that turns an API failure into a block, and the
// heartbeat is the first thing in a session that can learn it. It was recorded in memory only: the
// identity-bound `writeCache` seam was wired to the checker's `onSync` and to nothing else. So an org
// whose opt-out was learned from a heartbeat had it evaporate on `/reload` or on the next process,
// where `hydrateFromCache` found nothing and a cold start fails open — the exact posture that org
// paid to leave. Both paths now go through the same `makeCacheSync` closure, so they cannot diverge
// on the identity (gateway URL + key fingerprint) they bind the file to.
//
// **The two-timestamp rule is the soft spot this file exists to guard.** No heartbeat shape available
// today returns `tools_to_check` (§C2): the `session_start` event name lands on
// `preToolUseHandler.ts:1008-1012`, which carries no policy payload. So a heartbeat may bump
// `fetched_at` and must NEVER stamp `tools_synced_at` — stamping it would mean a first-ever session
// caching a *fresh* empty tool list and skipping every native file tool for 300 s, which is the
// upstream Python bug (`unbound.py:258-299`) that splitting the two timestamps exists to prevent.
// Asserted on the raw file keys, not just on the parsed value, because "absent" and "present but
// undefined" are different files.
//
// **Declaration order matters**, as in `compose.test.ts`: `policyState` is a module-scope singleton.
// Nothing in this file may ever stamp tools freshness in memory (no heartbeat can, which is the
// point), so the hydrate-preservation case below can still learn a tool list from disk.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { keyFingerprint, readCache, resolveCachePath, writeCache } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import { CACHE_TTL_MS, ENGINE_UNAVAILABLE_REASON, PRETOOL_PATH } from "../../core/src/constants.ts";
import { createHeartbeatGate } from "../../core/src/heartbeat.ts";
import { buildPretoolPayload } from "../../core/src/payload.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeCtx, createFakeSessionStartEvent } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const ENTRYPOINT = "pi/0.87.1";
const OLD_SYNCED_AT = 1_600_000_000_000;

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));
const pretoolCalls = (api: MockApi) => api.requests.filter((r) => r.path === PRETOOL_PATH);

interface Fixture {
  handler: AnyHandler;
  homeDir: string;
  cachePath: string;
  cleanup(): void;
}

/**
 * The extension against a throwaway HOME, plus the cache path the composition root will resolve from
 * that HOME — derived with the same function the adapter uses, so the test cannot assert against a
 * path the code does not write.
 */
async function fixture(api: MockApi): Promise<Fixture> {
  const homeDir = mkdtempSync(join(tmpdir(), "pi-hbcache-"));
  const env = { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url };
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension({
    env,
    homeDir,
    entrypoint: ENTRYPOINT,
    // A cold gate with the real rule, so this session's heartbeat is actually sent.
    heartbeatGate: createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS }) as Deps["heartbeatGate"],
  })(pi as unknown as ExtensionAPI);

  const handler = handlers.get("session_start");
  assert.ok(handler !== undefined, "session_start must be registered");
  const cachePath = resolveCachePath(env, homeDir);
  assert.ok(cachePath !== undefined, "the fixture must resolve a cache path");
  return {
    handler,
    homeDir,
    cachePath,
    cleanup: () => rmSync(homeDir, { recursive: true, force: true }),
  };
}

/** The file as written, unparsed by `readCache`, so key PRESENCE can be asserted. */
function rawCache(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

test("a heartbeat-learned block reaches the cache file, identity-bound", async () => {
  // `failBlock`'s first response is `{decision: allow, policy_check_failure_action: block}` with no
  // `tools_to_check` — the shape a real heartbeat gets.
  const api = await startMockApi({ mode: "failBlock" });
  const f = await fixture(api);
  try {
    await f.handler(createFakeSessionStartEvent("startup"), createFakeCtx());
    await sleep(80); // the heartbeat is fire-and-forget by contract
    assert.equal(pretoolCalls(api).length, 1, "the heartbeat was sent");

    const onDisk = readCache(f.cachePath, {
      gatewayUrl: api.url,
      fingerprint: keyFingerprint(TEST_KEY),
    });
    assert.ok(onDisk !== undefined, "the heartbeat response was persisted at all");
    assert.equal(onDisk.policy_check_failure_action, "block", "the opt-out is on disk");
    assert.equal(typeof onDisk.fetched_at, "number", "and the fetch is stamped");

    // Bound to the same identity the checker's `onSync` uses — a different gateway or key must not
    // be able to read this file.
    const raw = rawCache(f.cachePath);
    assert.equal(raw["gateway_url"], api.url);
    assert.equal(raw["key_fingerprint"], keyFingerprint(TEST_KEY));
    assert.equal(
      readCache(f.cachePath, { gatewayUrl: "http://127.0.0.1:1", fingerprint: keyFingerprint(TEST_KEY) }),
      undefined,
      "a foreign gateway reads nothing",
    );

    // The two-timestamp rule, on the raw keys: a heartbeat carries no tool list, so it must not
    // claim one is fresh — not as a value, and not as a key.
    assert.equal("tools_synced_at" in raw, false, `tools_synced_at must be absent: ${JSON.stringify(raw)}`);
    assert.equal("tools_to_check" in raw, false, "and so must the list it would age");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a heartbeat never bumps a tools_synced_at it inherited from disk", async () => {
  const api = await startMockApi({ mode: "failBlock" });
  const f = await fixture(api);
  try {
    // A previous session learned a real tool list. Seeded through the real writer, so the file is the
    // shape the adapter would have left behind.
    writeCache(f.cachePath, {
      gateway_url: api.url,
      key_fingerprint: keyFingerprint(TEST_KEY),
      fetched_at: OLD_SYNCED_AT,
      tools_synced_at: OLD_SYNCED_AT,
      tools_to_check: ["read", "write"],
      policy_check_failure_action: "allow",
    });

    await f.handler(createFakeSessionStartEvent("resume"), createFakeCtx());
    await sleep(80);

    const raw = rawCache(f.cachePath);
    assert.equal(
      raw["tools_synced_at"],
      OLD_SYNCED_AT,
      "the inherited stamp is preserved verbatim, never refreshed by a response that carried no list",
    );
    assert.deepEqual(raw["tools_to_check"], ["read", "write"], "and the list itself survives");
    assert.equal(raw["policy_check_failure_action"], "block", "while the new opt-out is learned");
    assert.ok(
      typeof raw["fetched_at"] === "number" && raw["fetched_at"] > OLD_SYNCED_AT,
      `fetched_at is the timestamp a heartbeat MAY move: ${String(raw["fetched_at"])}`,
    );
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("after a restart the persisted block turns the first failed tool call into a BLOCK", async () => {
  // The whole point of persisting it. A fresh `PolicyState` is what a new process has — the
  // module-scope singleton cannot be reset, and this is the state `hydrateFromCache` feeds.
  const api = await startMockApi({ mode: "failBlock" });
  const f = await fixture(api);
  try {
    await f.handler(createFakeSessionStartEvent("startup"), createFakeCtx());
    await sleep(80);

    // ---- the restart ----
    const restarted = createPolicyState();
    assert.equal(restarted.getFailureAction(), undefined, "a new process starts knowing nothing");
    const onDisk = readCache(f.cachePath, {
      gatewayUrl: api.url,
      fingerprint: keyFingerprint(TEST_KEY),
    });
    assert.ok(onDisk !== undefined);
    restarted.hydrate(onDisk);
    assert.equal(restarted.getFailureAction(), "block", "the opt-out survived the restart");

    // ---- the first tool call of the new process, against a failing gateway ----
    api.setMode("500");
    const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: 200 });
    const checker = createPolicyChecker({
      client,
      state: restarted,
      telemetry: { reportBypass: () => {} },
    });
    const payload = buildPretoolPayload({
      toolName: "bash",
      command: "cat /etc/shadow",
      toolInput: { command: "cat /etc/shadow" },
      cwd: "/tmp/project",
      sessionId: "sess-restart",
      model: "claude-sonnet-4-6",
      clientEntrypoint: ENTRYPOINT,
    });

    assert.deepEqual(
      await checker.checkTool(payload, "bash"),
      { kind: "unavailable" },
      "fail-CLOSED, because the cache remembered — this allowed before the fix",
    );
    assert.match(ENGINE_UNAVAILABLE_REASON, /policy engine unavailable/);
  } finally {
    f.cleanup();
    await api.close();
  }
});
