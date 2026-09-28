// The composition root — `createExtension`'s `init()` and `defaultMakeChecker`.
//
// Everything Wave 1 and Wave 2 added to core is reachable only through this file: the on-disk policy
// cache, the circuit breaker, the revoked-key latch and the category-aware reporter are all injected
// options with safe defaults, which means a wiring mistake here is silent. `cache.ts` in particular
// was unit-tested in 09-01 but was not in the bundle at all until now. So these cases assert the
// wiring itself — with a temp HOME, a real mock gateway and the real file modes.
//
// **Test order is load-bearing in this file.** `policyState` and `keyState` are module-scope
// singletons (they have to outlive a tool call to mean anything), so the hydration case runs first,
// while nothing has been learned from the network, and the latch case runs LAST, because a latched
// key is deliberately permanent for the life of the process.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { keyFingerprint, readCache, resolveCachePath } from "../../core/src/cache.ts";
import { resolveGatewayUrl } from "../../core/src/config.ts";
import {
  ENGINE_UNAVAILABLE_REASON,
  ERRORS_PATH,
  KEY_REJECTED_NOTICE,
  PRETOOL_PATH,
} from "../../core/src/constants.ts";
import { buildPretoolPayload } from "../../core/src/payload.ts";
import { policyState } from "../../core/src/policyState.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension, defaultMakeChecker } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx } from "./helpers/fakeCtx.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";


type AnyHandler = (event: unknown, ctx: unknown) => unknown;

interface Stub {
  handlers: Map<string, AnyHandler>;
}

async function build(overrides: Partial<Deps>): Promise<Stub> {
  const handlers = new Map<string, AnyHandler>();
  const api = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension(overrides)(api as unknown as ExtensionAPI);
  return { handlers };
}

async function toolCall(stub: Stub, ctx: FakeCtx): Promise<{ block?: boolean; reason?: string } | undefined> {
  const handler = stub.handlers.get("tool_call");
  assert.ok(handler !== undefined, "the tool_call handler is registered");
  return (await handler(
    createFakeToolCallEvent("bash", { command: "cat /etc/shadow" }),
    ctx,
  )) as { block?: boolean; reason?: string } | undefined;
}

const pretoolCalls = (api: MockApi) => api.requests.filter((r) => r.path === PRETOOL_PATH);
const errorReports = (api: MockApi) => api.requests.filter((r) => r.path === ERRORS_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

interface Fixture {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  cachePath: string;
  gatewayUrl: string;
  fingerprint: string;
  cleanup(): void;
}

/** A throwaway HOME plus the identity the cache will be keyed on, computed by the real resolvers. */
function fixture(api: MockApi): Fixture {
  const homeDir = mkdtempSync(join(tmpdir(), "pi-compose-"));
  const env: NodeJS.ProcessEnv = {
    UNBOUND_PI_API_KEY: TEST_KEY,
    UNBOUND_GATEWAY_URL: api.url,
  };
  const cachePath = resolveCachePath(env, homeDir);
  assert.ok(cachePath !== undefined, "a temp HOME resolves a cache path");
  return {
    env,
    homeDir,
    cachePath,
    // Taken from the same functions the extension uses, so the test cannot drift from the wiring.
    gatewayUrl: resolveGatewayUrl(env, homeDir),
    fingerprint: keyFingerprint(TEST_KEY),
    cleanup: () => rmSync(homeDir, { recursive: true, force: true }),
  };
}

function plantCache(path: string, record: Record<string, unknown>): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(record), { encoding: "utf8", mode: 0o600 });
}

function payload(): ReturnType<typeof buildPretoolPayload> {
  return buildPretoolPayload({
    toolName: "bash",
    command: "cat /etc/shadow",
    toolInput: { command: "cat /etc/shadow" },
    cwd: "/tmp/project",
    sessionId: "sess-compose",
    model: "claude-sonnet-4-6",
    clientEntrypoint: "pi/0.87.1",
  });
}

// --- init() hydrates the cache ------------------------------------------------------------------
//
// FIRST, deliberately: `hydrate` only fills what this process has not already learned from the
// network, so any earlier case that recorded a success would make this one vacuous.

test("the composition root hydrates a matching cache at init", async () => {
  const api = await startMockApi({ mode: "500" });
  const f = fixture(api);
  try {
    plantCache(f.cachePath, {
      fetched_at: Date.now(),
      policy_check_failure_action: "block",
      gateway_url: f.gatewayUrl,
      key_fingerprint: f.fingerprint,
    });

    const stub = await build({ env: f.env, homeDir: f.homeDir, entrypoint: "pi/0.87.1" });
    const result = await toolCall(stub, createFakeCtx());

    assert.equal(
      policyState.getFailureAction(),
      "block",
      "the remembered fail-open opt-out survived a restart",
    );
    // And it is load-bearing, not merely stored: the gateway is failing, and this org blocks.
    assert.deepStrictEqual(result, { block: true, reason: ENGINE_UNAVAILABLE_REASON });
    assert.equal(pretoolCalls(api).length, 1, "a hydrated block still costs a real attempt (§F8)");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("one successful check writes the cache back, 0600 in a 0700 directory", async () => {
  const api = await startMockApi({ mode: "toolsList" });
  const f = fixture(api);
  try {
    const stub = await build({ env: f.env, homeDir: f.homeDir, entrypoint: "pi/0.87.1" });
    assert.equal(await toolCall(stub, createFakeCtx()), undefined, "toolsList answers allow");

    const stat = statSync(f.cachePath);
    assert.equal(stat.mode & 0o777, 0o600, "a 0644 cache is a file any local process could rewrite");
    assert.equal(statSync(dirname(f.cachePath)).mode & 0o777, 0o700);

    const raw = readFileSync(f.cachePath, "utf8");
    const record = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(record.gateway_url, f.gatewayUrl, "half the cache key");
    assert.equal(record.key_fingerprint, f.fingerprint, "the other half");
    assert.deepEqual(record.tools_to_check, ["read", "write"], "the wire value round-tripped");
    assert.equal(typeof record.tools_synced_at, "number");
    assert.equal(raw.includes(TEST_KEY), false, "the key itself never reaches disk (T-09-14)");

    // And it reads back through the real reader under the real identity.
    const reread = readCache(f.cachePath, { gatewayUrl: f.gatewayUrl, fingerprint: f.fingerprint });
    assert.deepEqual(reread?.tools_to_check, ["read", "write"]);
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a foreign, missing or unreadable cache leaves the extension working normally", async () => {
  const api = await startMockApi({ mode: "deny" });
  const f = fixture(api);
  try {
    // Another tenant's gateway — the record must not be handed to this one (T-09-02).
    plantCache(f.cachePath, {
      fetched_at: Date.now(),
      policy_check_failure_action: "block",
      tools_to_check: [],
      tools_synced_at: Date.now(),
      gateway_url: "https://someone-elses-gateway.example.com",
      key_fingerprint: f.fingerprint,
    });
    assert.equal(
      readCache(f.cachePath, { gatewayUrl: f.gatewayUrl, fingerprint: f.fingerprint }),
      undefined,
      "a foreign identity is a miss",
    );

    const stub = await build({ env: f.env, homeDir: f.homeDir, entrypoint: "pi/0.87.1" });
    const result = await toolCall(stub, createFakeCtx());
    assert.equal(result?.block, true, "the extension still enforces off the network");
    assert.equal(pretoolCalls(api).length, 1);

    // No cache at all: a cold start, still not an error.
    rmSync(f.cachePath, { force: true });
    const cold = await build({ env: f.env, homeDir: f.homeDir, entrypoint: "pi/0.87.1" });
    let again: unknown;
    await assert.doesNotReject(async () => {
      again = await toolCall(cold, createFakeCtx());
    }, "a missing cache is a cold start");
    assert.equal((again as { block?: boolean })?.block, true);
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("defaultMakeChecker builds one breaker per resolved base URL", async () => {
  const failing = await startMockApi({ mode: "500" });
  const healthy = await startMockApi({ mode: "allow" });
  try {
    // No env and no home ⇒ `resolveCachePath` refuses, so neither checker touches a filesystem.
    const first = defaultMakeChecker(TEST_KEY, failing.url);
    const second = defaultMakeChecker(TEST_KEY, healthy.url);

    // Normalise the shared policyState away from any hydrated `block`, so the breaker applies.
    await second.checkTool(payload(), "bash");
    assert.notEqual(policyState.getFailureAction(), "block");

    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(await first.checkTool(payload(), "bash"), { kind: "allow" });
    }
    assert.equal(pretoolCalls(failing).length, 3, "three real attempts");

    await first.checkTool(payload(), "bash");
    assert.equal(pretoolCalls(failing).length, 3, "the first gateway is out of circuit");

    const healthyBefore = pretoolCalls(healthy).length;
    assert.deepEqual(await second.checkTool(payload(), "bash"), { kind: "allow" });
    assert.equal(
      pretoolCalls(healthy).length,
      healthyBefore + 1,
      "a second gateway is not implicated by the first's outage",
    );
  } finally {
    await failing.close();
    await healthy.close();
  }
});

// --- WR-01 through the whole extension ----------------------------------------------------------
//
// LAST in the file: the latch is module-scope and permanent by design, so every case after this one
// would see an inactive session. That permanence is the feature — `/reload` is the recovery path.

test("the key latch is shared with the reporter: one notice, then no HTTP of any kind", async () => {
  const api = await startMockApi({ mode: "401" });
  const f = fixture(api);
  try {
    const stub = await build({ env: f.env, homeDir: f.homeDir, entrypoint: "pi/0.87.1" });
    const ctx = createFakeCtx();

    assert.equal(await toolCall(stub, ctx), undefined, "a 401 fails open");
    assert.equal(await toolCall(stub, ctx), undefined, "and the second latches");
    await sleep(80);

    const notices = ctx.notifyCalls.filter((n) => n.message === KEY_REJECTED_NOTICE);
    assert.equal(notices.length, 1, `exactly one in-editor notice: ${JSON.stringify(ctx.notifyCalls)}`);
    assert.equal(notices[0]?.type, "warning");

    const pretoolAfter = pretoolCalls(api).length;
    const errorsAfter = errorReports(api).length;
    assert.equal(pretoolAfter, 2, "it stopped at two attempts");

    for (let i = 0; i < 3; i += 1) {
      assert.equal(await toolCall(stub, ctx), undefined, "an inactive session never blocks");
    }
    await sleep(80);
    assert.equal(pretoolCalls(api).length, pretoolAfter, "zero further policy requests");
    assert.equal(
      errorReports(api).length,
      errorsAfter,
      "and zero further /v1/hooks/errors — the reporter shares the latch",
    );
    assert.equal(ctx.notifyCalls.length, 1, "and the notice is never repeated");
  } finally {
    f.cleanup();
    await api.close();
  }
});
