// HOOK-02 — pi's six native file tools on the wire, plus the notice channel the `tool_call` path
// depends on.
//
// Two independent things are pinned here:
//
//   1. **The path contract.** `read`/`write`/`edit` send `command: ""` and a `metadata.file_path`;
//      `grep`/`find`/`ls` default that path to the cwd, because pi makes `path` optional on them
//      while the server's Path-2 entry gate needs `!!command || (nativeTool && !!file_path)` — a
//      pathless search would otherwise skip policy evaluation entirely. The mock models that gate,
//      so a forgotten `file_path` fails here instead of passing vacuously.
//   2. **`hooks.notify` actually reaching the editor from the `tool_call` path.** 09-02 raises the
//      breaker-open and key-rejected notices through `checkTool`'s third argument. Those assertions
//      live in `breaker.test.ts` / `inactive.test.ts`, which call `checkTool` directly — so without
//      the two cases at the bottom of this file the wiring's first test would be a human looking at
//      a TUI (SMOKE row 16). These drive the real breaker and the real latch through
//      `decideToolCall`.
//
// Notice literals are spelled out rather than imported, for the reason `decision.test.ts` gives:
// importing the constant would let a typo retune the assertion instead of failing it.

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../../core/src/client.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { decideToolCall } from "../src/decide.ts";
import type { DecideDeps } from "../src/decide.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";

/** WR-02's open notice, as locked by 09-CONTEXT.md. */
const BREAKER_OPEN = "Unbound policy engine unreachable — allowing tool calls for 60 s";
/** WR-01's latch notice, likewise. */
const KEY_REJECTED = "Unbound: API key rejected — enforcement inactive";

interface DepsOptions {
  state?: PolicyState;
  now?: () => number;
}

function depsFor(api: MockApi, opts: DepsOptions = {}): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
  // One state object for both the checker and the adapter: the skip decision and the recorded
  // response have to be talking about the same memory, or the test proves nothing.
  const state = opts.state ?? createPolicyState();
  return {
    checker: createPolicyChecker({
      client,
      state,
      telemetry: createTelemetry({ client, apiKey: TEST_KEY }),
      now: opts.now,
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
    state,
    now: opts.now,
  };
}

function pretoolBodies(api: MockApi): Record<string, unknown>[] {
  return api.requests
    .filter((r) => r.path === PRETOOL_PATH)
    .map((r) => r.body as Record<string, unknown>);
}

interface PreToolUseDataLike {
  tool_name?: string;
  command?: string;
  tool_use_id?: string;
  metadata?: Record<string, unknown>;
}

function dataOf(body: Record<string, unknown> | undefined): PreToolUseDataLike {
  return (body?.pre_tool_use_data ?? {}) as PreToolUseDataLike;
}

/** Run one `tool_call` against a freshly started mock and hand back everything worth asserting. */
async function runOne(
  mode: MockMode,
  toolName: string,
  input: Record<string, unknown>,
  cwd = "/tmp/project-x",
): Promise<{
  result: { block?: boolean; reason?: string } | undefined;
  bodies: Record<string, unknown>[];
  notifyCalls: { message: string; type: string | undefined }[];
}> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx({ cwd });
  try {
    const result = await decideToolCall(
      createFakeToolCallEvent(toolName, input),
      ctx,
      depsFor(api),
    );
    return { result, bodies: pretoolBodies(api), notifyCalls: ctx.notifyCalls };
  } finally {
    await api.close();
  }
}

test("HOOK-02 read, write and edit send command:'' plus metadata.file_path", async () => {
  for (const toolName of ["read", "write", "edit"]) {
    const { bodies } = await runOne("allow", toolName, { path: "/x/y" });

    assert.equal(bodies.length, 1, `${toolName} must be evaluated`);
    const data = dataOf(bodies[0]);
    assert.equal(data.tool_name, toolName, "the lowercase pi name is forwarded verbatim");
    assert.equal(data.command, "", "a file tool carries no command (§B3)");
    assert.equal(data.metadata?.file_path, "/x/y", "the path is what the server evaluates");
  }
});

test("HOOK-02 grep, find and ls with no path default file_path to the cwd", async () => {
  for (const toolName of ["grep", "find", "ls"]) {
    const { bodies } = await runOne("allow", toolName, {}, "/tmp/pathless-search");

    assert.equal(bodies.length, 1, `${toolName} must still be evaluated`);
    const data = dataOf(bodies[0]);
    assert.equal(data.tool_name, toolName);
    assert.equal(
      data.metadata?.file_path,
      "/tmp/pathless-search",
      "without this the entry gate answers allow and the search runs unchecked",
    );
  }
});

test("HOOK-02 a grep with an explicit path keeps it, and forwards tool_input.pattern", async () => {
  const { bodies } = await runOne("allow", "grep", { path: "/srv/app", pattern: "TODO" });

  const data = dataOf(bodies[0]);
  assert.equal(data.metadata?.file_path, "/srv/app", "an explicit path beats the cwd default");
  const toolInput = data.metadata?.tool_input as Record<string, unknown>;
  assert.equal(toolInput.pattern, "TODO", "`pattern` is the one tool_input key an evaluator reads");
});

test("HOOK-02 a file tool the server denies is blocked, with the reason prefixed and notified", async () => {
  const { result, notifyCalls } = await runOne("deny", "read", { path: "/etc/shadow" });

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(notifyCalls.length, 1);
  assert.deepStrictEqual(notifyCalls[0], {
    message: "Reading secrets is blocked.",
    type: "error",
  });
});

test("HOOK-02 a write's file body never reaches the wire, only its path", async () => {
  const { bodies } = await runOne("allow", "write", {
    path: "/srv/app/.env",
    content: "SECRET_TOKEN=hunter2-do-not-exfiltrate",
  });

  const serialised = JSON.stringify(bodies);
  assert.equal(serialised.includes("hunter2"), false, "no substring of the body may appear");
  assert.equal(dataOf(bodies[0]).metadata?.file_path, "/srv/app/.env", "the path still ships");
});

test("HOOK-02 DecideDeps.state is injectable, so a test can start from nothing learned", async () => {
  const state = createPolicyState();
  assert.equal(state.getToolsSyncedAt(), undefined, "a fresh state has learned nothing");

  const api = await startMockApi({ mode: "toolsList" });
  const ctx = createFakeCtx();
  try {
    await decideToolCall(
      createFakeToolCallEvent("read", { path: "/x" }),
      ctx,
      depsFor(api, { state }),
    );
    // The injected instance is the one the checker recorded into — not the module singleton, which
    // would carry whatever an earlier test in this process happened to teach it.
    assert.notEqual(state.getToolsSyncedAt(), undefined, "the response was recorded here");
    assert.deepStrictEqual(state.getToolsToCheck(), ["read", "write"]);
  } finally {
    await api.close();
  }
});

// The `hooks.notify` pass-through. `decideToolCall` binds the live `ctx` into `checkTool`'s third
// argument; these three cases prove the channel exists, and that both of 09-02's notices travel it
// on the `tool_call` path specifically.

test("HOOK-02 the default hooks channel carries a core notice to the live ctx", async () => {
  const ctx = createFakeCtx();
  const result = await decideToolCall(
    createFakeToolCallEvent("read", { path: "/x" }),
    ctx,
    {
      // A stub checker standing in for any core mechanism that raises a notice.
      checker: {
        async checkTool(_payload, _toolName, hooks) {
          hooks?.notify?.("probe notice from core", "warning");
          return { kind: "allow" };
        },
      },
      apiKey: TEST_KEY,
      entrypoint: "pi/0.87.1",
    },
  );

  assert.equal(result, undefined);
  assert.equal(ctx.notifyCalls.length, 1, "exactly one, and it arrived without being injected");
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: "probe notice from core",
    type: "warning",
  });
});

test("WR-02 a breaker opening during a tool_call notifies exactly once, on the tool_call path", async () => {
  // `hang` never answers, so each call fails on the client's own 50 ms deadline.
  const api = await startMockApi({ mode: "hang" });
  const ctx = createFakeCtx();
  const deps = depsFor(api);
  try {
    for (let i = 0; i < 3; i += 1) {
      const result = await decideToolCall(
        createFakeToolCallEvent("read", { path: `/x/${i}` }),
        ctx,
        deps,
      );
      assert.equal(result, undefined, "every failure fails open");
    }

    assert.equal(ctx.notifyCalls.length, 1, `got ${JSON.stringify(ctx.notifyCalls)}`);
    assert.deepStrictEqual(ctx.notifyCalls[0], { message: BREAKER_OPEN, type: "warning" });
    assert.equal(
      ctx.notifyCalls[0]?.message,
      "Unbound policy engine unreachable — allowing tool calls for 60 s",
      "byte-identical to the locked literal",
    );

    const before = pretoolBodies(api).length;
    await decideToolCall(createFakeToolCallEvent("read", { path: "/x/4" }), ctx, deps);
    assert.equal(pretoolBodies(api).length, before, "an open breaker makes no request");
    assert.equal(ctx.notifyCalls.length, 1, "and does not re-announce");
  } finally {
    await api.close();
  }
});

test("WR-01 a key latching during a tool_call notifies exactly once, on the tool_call path", async () => {
  const api = await startMockApi({ mode: "401" });
  const ctx = createFakeCtx();
  const deps = depsFor(api);
  try {
    for (let i = 0; i < 2; i += 1) {
      const result = await decideToolCall(
        createFakeToolCallEvent("read", { path: `/x/${i}` }),
        ctx,
        deps,
      );
      assert.equal(result, undefined, "a rejected key never blocks");
    }

    assert.equal(ctx.notifyCalls.length, 1, `got ${JSON.stringify(ctx.notifyCalls)}`);
    assert.deepStrictEqual(ctx.notifyCalls[0], { message: KEY_REJECTED, type: "warning" });
    assert.equal(
      ctx.notifyCalls[0]?.message,
      "Unbound: API key rejected — enforcement inactive",
      "byte-identical to the locked literal",
    );

    const before = pretoolBodies(api).length;
    await decideToolCall(createFakeToolCallEvent("read", { path: "/x/2" }), ctx, deps);
    assert.equal(pretoolBodies(api).length, before, "a latched session makes no request");
    assert.equal(ctx.notifyCalls.length, 1, "one notice per process, not per call");
  } finally {
    await api.close();
  }
});
