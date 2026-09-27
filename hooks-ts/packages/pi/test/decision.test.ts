// HOOK-01 — the verdict-to-pi-behaviour mapping, driven through the real core composition against
// the scripted mock gateway.
//
// The user-facing strings are asserted as LITERALS, not by importing `constants.ts`. Importing the
// constant would make the assertion self-fulfilling: a typo in the constant would silently retune
// the test instead of failing it. These strings are locked by 08-CONTEXT.md and are what the model
// and the developer actually read (§B5), so they are spelled out here on purpose.
//
// Every client is built with `timeoutMs: 50`, so the whole suite runs in milliseconds.

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../../core/src/client.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { ATTRIBUTION_SUFFIX, startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { decideToolCall } from "../src/decide.ts";
import type { DecideDeps } from "../src/decide.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx, FakeCtxOptions } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";

function depsFor(api: MockApi): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
  return {
    checker: createPolicyChecker({
      client,
      state: createPolicyState(),
      telemetry: createTelemetry({ client, apiKey: TEST_KEY }),
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
  };
}

/** Only the policy calls; a fail-open bypass self-report also lands in `api.requests`. */
function pretoolRequests(api: MockApi): unknown[] {
  return api.requests.filter((r) => r.path === PRETOOL_PATH);
}

interface RunResult {
  result: { block?: boolean; reason?: string } | undefined;
  api: MockApi;
  ctx: FakeCtx;
}

/**
 * Start the mock in `mode`, run one bash `tool_call` through the adapter, close the mock.
 * `body` lets a caller inspect the captured wire body before teardown.
 */
async function run(
  mode: MockMode,
  opts: {
    toolName?: string;
    input?: Record<string, unknown>;
    ctx?: Partial<FakeCtxOptions>;
    /** Extra calls to make before the asserted one (used to prime `failBlock`). */
    warmups?: number;
  } = {},
): Promise<RunResult> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx(opts.ctx);
  const deps = depsFor(api);
  try {
    for (let i = 0; i < (opts.warmups ?? 0); i += 1) {
      await decideToolCall(
        createFakeToolCallEvent("bash", { command: "echo warmup" }),
        ctx,
        deps,
      );
    }
    const event = createFakeToolCallEvent(
      opts.toolName ?? "bash",
      opts.input ?? { command: "cat /etc/shadow" },
    );
    const result = await decideToolCall(event, ctx, deps);
    return { result, api, ctx };
  } finally {
    await api.close();
  }
}

test("HOOK-01 deny: the API reason is prefixed verbatim and notified as an error", async () => {
  const { result, ctx } = await run("deny");

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(ctx.notifyCalls.length, 1, "exactly one notification");
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: "Reading secrets is blocked.",
    type: "error",
  });
});

test("HOOK-01 deny with no reason: the generic string, never undefined", async () => {
  const { result } = await run("denyNoReason");

  assert.deepStrictEqual(result, { block: true, reason: "Blocked by Unbound policy." });
  assert.notEqual(result?.reason, undefined);
  assert.equal(result?.reason?.includes("undefined"), false, "no stringified undefined");
});

test("HOOK-01 deny: the attribution footer survives byte-for-byte at the end", async () => {
  const { result } = await run("attributed");

  const reason = result?.reason ?? "";
  assert.ok(reason.startsWith("Blocked by Unbound policy: "), `prefix missing in ${reason}`);
  assert.ok(reason.endsWith(ATTRIBUTION_SUFFIX), "footer must remain last");
  assert.ok(reason.endsWith("\n\nEnforced by Unbound · Trace ID abc"), "footer verbatim");
});

test("HOOK-01 deny: the block result carries no batch-termination key", async () => {
  const { result } = await run("deny");

  assert.ok(result !== undefined);
  assert.equal(Object.hasOwn(result, "terminate"), false, "Phase 8 never sets it (§A3)");
});

test("HOOK-01 allow: returns undefined and never mutates event.input", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  try {
    const event = createFakeToolCallEvent("bash", { command: "echo hi", timeout: 30 });
    const before = structuredClone(event.input);

    const result = await decideToolCall(event, ctx, depsFor(api));

    assert.equal(result, undefined);
    assert.deepStrictEqual(event.input, before, "event.input is read-only in Phase 8 (§F9)");
    assert.equal(ctx.notifyCalls.length, 0, "an allow is silent");
    assert.equal(pretoolRequests(api).length, 1);
  } finally {
    await api.close();
  }
});

test("HOOK-01 empty bash command: zero HTTP requests (§B3)", async () => {
  const { result, api } = await run("deny", { input: { command: "" } });

  assert.equal(result, undefined, "an empty command is nothing to evaluate");
  assert.equal(api.requests.length, 0, "no round trip at all");
});

test("HOOK-01 whitespace-only bash command: zero HTTP requests (§B3)", async () => {
  const { result, api } = await run("deny", { input: { command: "   " } });

  assert.equal(result, undefined);
  assert.equal(api.requests.length, 0);
});

test("HOOK-01 a pathless non-bash tool still sends metadata.file_path = cwd", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx({ cwd: "/tmp/project-x" });
  try {
    const result = await decideToolCall(
      createFakeToolCallEvent("grep", { pattern: "x" }),
      ctx,
      depsFor(api),
    );

    assert.equal(result, undefined);
    const requests = pretoolRequests(api);
    assert.equal(requests.length, 1, "a non-bash tool is still evaluated");
    const body = api.requests[0]?.body as {
      pre_tool_use_data?: { tool_name?: string; metadata?: Record<string, unknown> };
    };
    assert.equal(body.pre_tool_use_data?.tool_name, "grep");
    assert.equal(body.pre_tool_use_data?.metadata?.file_path, "/tmp/project-x");
  } finally {
    await api.close();
  }
});

test("HOOK-01 the wire body carries the pi identity taken from ctx", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx({ sessionId: "sess-pi-42", modelId: "claude-sonnet-4-5" });
  try {
    await decideToolCall(
      createFakeToolCallEvent("bash", { command: "ls -la" }, "toolu_xyz"),
      ctx,
      depsFor(api),
    );

    const body = api.requests[0]?.body as Record<string, unknown>;
    assert.equal(body.conversation_id, "sess-pi-42");
    assert.equal(body.model, "claude-sonnet-4-5");
    assert.equal(body.unbound_app_label, "pi");
    assert.equal(body.client_entrypoint, "pi/0.87.1");
    const data = body.pre_tool_use_data as Record<string, unknown>;
    assert.equal(data.tool_name, "bash");
    assert.equal(data.command, "ls -la");
    assert.equal(data.tool_use_id, "toolu_xyz");
  } finally {
    await api.close();
  }
});

test("RES-01 a remembered block-on-failure turns a failure into the unavailable block", async () => {
  // `failBlock` answers the first call with `policy_check_failure_action: 'block'`, then hangs.
  const { result } = await run("failBlock", { warmups: 1 });

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Unbound policy engine unavailable — please retry",
  });
});
