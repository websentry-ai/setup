// Resilience over the whole opencode plugin (RES-07, RES-08, RES-11), through the real plugin entry
// against the core mock API. Small injected timeouts only: no test waits on the real 20 s deadline.
//
//   RES-07  black-holed gateway: each call is bounded by the deadline; once the per-URL breaker opens
//           later calls skip without a request; the production factory keeps core's deadline.
//   RES-08  the 300 s policy cache honours `tools_to_check` for opencode's native file tools, is
//           written 0600 under the opencode config dir, and a hydrated cache still forces one pull.
//   RES-11  a revoked key is noticed once and stops all requests; a fail-closed org blocks; blocked
//           and bypassed failures land in distinct categories.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import {
  BREAKER_FAILURE_THRESHOLD,
  BREAKER_OPEN_NOTICE,
  CACHE_DIR_NAME,
  CACHE_FILE_NAME,
  CACHE_TTL_MS,
  ENGINE_UNAVAILABLE_REASON,
  ERROR_CATEGORY_BLOCKED,
  ERROR_CATEGORY_BYPASS,
  KEY_REJECTED_NOTICE,
} from "../../core/src/constants.ts";
import { createScopedStates } from "../../core/src/scopedState.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createServerPlugin } from "../src/plugin.ts";
import { pretoolRequests, signalsOf, startOpencodeMock, tick, TEST_KEY, waitFor } from "./helpers/fakeHost.ts";
import { outcome, startHarness } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const S = "ses_root";
const SMALL = { timeouts: { pretoolMs: 150, errorsMs: 500, turnLogMs: 500 }, deadlineMs: 400 } as const;

let callSeq = 0;
function bash(h: { hook(name: string): (...a: unknown[]) => Promise<unknown> }, command = "ls"): Promise<unknown> {
  callSeq += 1;
  return h.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: `c${callSeq}` }, { args: { command } });
}

function fileCall(
  h: { hook(name: string): (...a: unknown[]) => Promise<unknown> },
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  callSeq += 1;
  return h.hook("tool.execute.before")({ tool, sessionID: S, callID: `f${callSeq}` }, { args });
}

async function timed(p: Promise<unknown>): Promise<{ ms: number; message: string | undefined }> {
  const start = Date.now();
  const message = await outcome(p);
  return { ms: Date.now() - start, message };
}

// --- RES-07 ---------------------------------------------------------------------------------------

test("RES-07 black-holed gateway: calls are bounded by the deadline, then the breaker skips without a request", async () => {
  const h = await startHarness(mock, "hang", { deps: { ...SMALL } });
  try {
    for (let i = 0; i < BREAKER_FAILURE_THRESHOLD; i += 1) {
      const r = await timed(bash(h));
      assert.equal(r.message, undefined, `call ${i + 1} allows (fail-open)`);
      assert.ok(r.ms >= 100, `call ${i + 1} waited for the timeout (${r.ms} ms)`);
      assert.ok(r.ms < 1000, `call ${i + 1} is bounded (${r.ms} ms)`);
    }
    const sent = pretoolRequests(mock).length;
    assert.equal(sent, BREAKER_FAILURE_THRESHOLD);
    const r = await timed(bash(h));
    assert.equal(r.message, undefined);
    assert.ok(r.ms < 50, `breaker-open call is immediate (${r.ms} ms)`);
    assert.equal(pretoolRequests(mock).length, sent, "no request while the breaker is open");
    await tick(50);
    assert.equal(h.fake.toasts.filter((t) => t.message === BREAKER_OPEN_NOTICE).length, 1, "breaker notice once");
    assert.ok(await waitFor(() => signalsOf(mock, ERROR_CATEGORY_BYPASS).length >= 1), "bypass reported");
  } finally {
    h.cleanup();
  }
});

test("RES-07 the production factory keeps core's deadline (no timeouts or deadline override)", () => {
  const server = createServerPlugin();
  const deps = server.inspect.runtime().deps;
  assert.equal(deps.timeouts, undefined);
  assert.equal(deps.deadlineMs, undefined);
});

// --- RES-08 ---------------------------------------------------------------------------------------

function cacheHome(): { home: string; env: NodeJS.ProcessEnv; cachePath: string; cleanup(): void } {
  const home = mkdtempSync(join(tmpdir(), "unbound-oc-res08-"));
  const xdg = join(home, "xdg");
  const env: NodeJS.ProcessEnv = {
    UNBOUND_GATEWAY_URL: mock.url,
    UNBOUND_OPENCODE_API_KEY: TEST_KEY,
    XDG_CONFIG_HOME: xdg,
  };
  return {
    home,
    env,
    cachePath: join(xdg, "opencode", CACHE_DIR_NAME, CACHE_FILE_NAME),
    cleanup: () => rmSync(home, { recursive: true, force: true }),
  };
}

test("RES-08 tools_to_check skips unlisted file tools, honours the TTL, and writes a 0600 cache that still forces one pull", async () => {
  const c = cacheHome();
  let clock = 1_000_000;
  const now = (): number => clock;
  try {
    const h = await startHarness(mock, "toolsList", { deps: { env: c.env, homeDir: c.home, now } });
    try {
      await fileCall(h, "read", { filePath: "/repo/a.txt" });
      let reqs = pretoolRequests(mock);
      assert.equal(reqs.length, 1);
      assert.equal((reqs[0]?.body as PretoolRequestBody & { pull_policies?: boolean }).pull_policies, true);

      // grep is a native file tool not in ["read","write"]: no request, recorded as skipped.
      await fileCall(h, "grep", { pattern: "x", path: "/repo" });
      assert.equal(pretoolRequests(mock).length, 1, "grep skipped");
      const turn = h.server.inspect.turn(S);
      assert.ok(turn.tool_calls.some((t) => t.tool_name === "grep" && t.decision === "skipped"));

      await fileCall(h, "read", { filePath: "/repo/b.txt" });
      assert.equal(pretoolRequests(mock).length, 2, "read (listed) is requested");
      await bash(h, "ls");
      assert.equal(pretoolRequests(mock).length, 3, "bash is always requested");

      clock += CACHE_TTL_MS + 1;
      await fileCall(h, "grep", { pattern: "x", path: "/repo" });
      reqs = pretoolRequests(mock);
      assert.equal(reqs.length, 4, "grep requested after the TTL");
      assert.equal((reqs[3]?.body as PretoolRequestBody & { pull_policies?: boolean }).pull_policies, true);

      assert.ok(await waitFor(() => existsSync(c.cachePath)), `cache written at ${c.cachePath}`);
      assert.equal(statSync(c.cachePath).mode & 0o777, 0o600);
    } finally {
      h.cleanup();
    }

    // A new plugin with fresh state over the same home: hydrated, yet its first call still pulls.
    const h2 = await startHarness(mock, "toolsList", {
      deps: { env: c.env, homeDir: c.home, now, scopes: createScopedStates() },
    });
    try {
      const scope = h2.server.inspect.runtime().init().scope;
      assert.ok(scope !== undefined);
      assert.deepEqual(scope.policy.snapshot().tools_to_check, ["read", "write"], "hydrated from disk");
      assert.equal(scope.policy.getToolsConfirmed(), false, "hydrate never confirms the list");
      await fileCall(h2, "grep", { pattern: "x", path: "/repo" });
      const reqs = pretoolRequests(mock);
      assert.equal(reqs.length, 1, "the first call is not skipped from a hydrated cache");
      assert.equal((reqs[0]?.body as PretoolRequestBody & { pull_policies?: boolean }).pull_policies, true);
    } finally {
      h2.cleanup();
    }
  } finally {
    c.cleanup();
  }
});

// --- RES-11 ---------------------------------------------------------------------------------------

test("RES-11 a revoked key is noticed once and stops every request, including the turn log", async () => {
  const h = await startHarness(mock, "401", { deps: { ...SMALL } });
  try {
    await h.hook("chat.message")({ sessionID: S }, { message: {}, parts: [{ type: "text", text: "hi" }] });
    await bash(h);
    await bash(h);
    await tick(50);
    assert.equal(h.fake.toasts.filter((t) => t.message === KEY_REJECTED_NOTICE).length, 1, "notice once");
    const before = mock.requests.length;
    assert.equal(await outcome(bash(h)), undefined);
    await h.emit("session.idle", { sessionID: S });
    await tick(100);
    assert.equal(mock.requests.length, before, "no request of any kind after the latch");
    assert.equal(mock.requests.filter((r) => r.path === "/v1/hooks/opencode").length, 0, "no turn log");
  } finally {
    h.cleanup();
  }
});

test("RES-11 a fail-closed org blocks under a dead gateway, filed as blocked (distinct from bypass)", async () => {
  const h = await startHarness(mock, "failBlock", { deps: { ...SMALL } });
  try {
    assert.equal(await outcome(bash(h)), undefined, "the first call learns failure_action=block");
    mock.setMode("hang");
    assert.equal(await outcome(bash(h)), ENGINE_UNAVAILABLE_REASON);
    assert.ok(await waitFor(() => signalsOf(mock, ERROR_CATEGORY_BLOCKED).length >= 1), "blocked reported");
    assert.equal(signalsOf(mock, ERROR_CATEGORY_BYPASS).length, 0, "not filed as a bypass");
    assert.notEqual(ERROR_CATEGORY_BLOCKED, ERROR_CATEGORY_BYPASS);
  } finally {
    h.cleanup();
  }
});
