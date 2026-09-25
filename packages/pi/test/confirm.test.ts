// HOOK-03 — the confirm path: ask / approval_required, accept, decline, headless, RPC, and a UI
// that explodes.
//
// Two invariants get most of the attention here:
//   * `ctx.ui.confirm` is ALWAYS called with a bounded `{timeout, signal}`. In `--mode rpc` `hasUI`
//     is true but an unbounded confirm never settles, and because pi gates the whole tool batch on
//     our handler (§F2) that freezes the agent outright (§F5). The `mode: "rpc"` test below is the
//     regression guard for exactly that.
//   * Anything other than picking "Yes" — No, Escape, dismissal, timeout, abort — resolves `false`
//     in pi (`interactive-mode.js:2073`), so one decline branch covers all of them (§A5).
//
// Strings are asserted as literals; see the note at the top of decision.test.ts.

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../../core/src/client.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { decideToolCall } from "../src/decide.ts";
import type { DecideDeps } from "../src/decide.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx, FakeCtxOptions } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;

const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";

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

async function run(
  mode: MockMode,
  ctxOverrides: Partial<FakeCtxOptions> = {},
  mutateCtx?: (ctx: FakeCtx) => void,
): Promise<{ result: { block?: boolean; reason?: string } | undefined; ctx: FakeCtx }> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx(ctxOverrides);
  mutateCtx?.(ctx);
  try {
    const result = await decideToolCall(
      createFakeToolCallEvent("bash", { command: "rm -rf /tmp/x" }),
      ctx,
      depsFor(api),
    );
    return { result, ctx };
  } finally {
    await api.close();
  }
}

test("HOOK-03 ask + accept: one bounded confirm, then the tool is allowed", async () => {
  const { result, ctx } = await run("ask", { confirmResult: true });

  assert.equal(result, undefined, "accepting allows the call");
  assert.equal(ctx.confirmCalls.length, 1, "exactly one dialog");

  const call = ctx.confirmCalls[0];
  assert.ok(call !== undefined);
  assert.equal(call.title, "Unbound policy");
  assert.ok(call.message.includes("Unusual command."), `reason missing from ${call.message}`);
  assert.ok(call.message.includes("Run this command?"), "the question is asked");
  assert.equal(typeof call.opts?.timeout, "number", "a confirm without a timeout can hang (§F5)");
  assert.ok((call.opts?.timeout ?? 0) > 0, "the timeout must be positive");
  assert.equal(call.opts?.signal, ctx.signal, "the turn's abort signal is forwarded");
});

test("HOOK-03 ask + decline: blocks with the locked decline reason", async () => {
  const { result, ctx } = await run("ask", { confirmResult: false });

  assert.deepStrictEqual(result, { block: true, reason: "Declined by user (Unbound policy)" });
  assert.equal(ctx.confirmCalls.length, 1);
});

test("HOOK-03 approval_required takes the identical confirm path", async () => {
  const accepted = await run("approval", { confirmResult: true });
  assert.equal(accepted.result, undefined);
  assert.equal(accepted.ctx.confirmCalls.length, 1);
  assert.equal(accepted.ctx.confirmCalls[0]?.title, "Unbound policy");
  assert.ok(accepted.ctx.confirmCalls[0]?.message.includes("Needs admin approval."));

  const declined = await run("approval", { confirmResult: false });
  assert.deepStrictEqual(declined.result, {
    block: true,
    reason: "Declined by user (Unbound policy)",
  });
});

test("HOOK-03 ask also notifies the reason as a warning so it survives the dialog", async () => {
  const { ctx } = await run("ask", { confirmResult: true });

  assert.equal(ctx.notifyCalls.length, 1, "exactly one notification");
  assert.deepStrictEqual(ctx.notifyCalls[0], { message: "Unusual command.", type: "warning" });
});

test("HOOK-03 headless: ask blocks with the no-UI reason and never opens a dialog", async () => {
  const { result, ctx } = await run("ask", { hasUI: false, mode: "json" });

  assert.deepStrictEqual(result, { block: true, reason: NO_UI_REASON });
  assert.equal(ctx.confirmCalls.length, 0, "there is nobody to ask");
});

test("HOOK-03 rpc mode (hasUI true): the confirm still carries a bounded timeout (§F5 guard)", async () => {
  const { result, ctx } = await run("ask", { mode: "rpc", hasUI: true, confirmResult: true });

  assert.equal(result, undefined);
  assert.equal(ctx.confirmCalls.length, 1);
  assert.equal(typeof ctx.confirmCalls[0]?.opts?.timeout, "number");
  assert.ok((ctx.confirmCalls[0]?.opts?.timeout ?? 0) > 0);
});

test("HOOK-03 ctx.signal undefined: the timeout is still passed and nothing throws", async () => {
  const api = await startMockApi({ mode: "ask" });
  const ctx = createFakeCtx({ signal: undefined, confirmResult: true });
  try {
    let result: { block?: boolean; reason?: string } | undefined;
    await assert.doesNotReject(async () => {
      result = await decideToolCall(
        createFakeToolCallEvent("bash", { command: "rm -rf /tmp/x" }),
        ctx,
        depsFor(api),
      );
    }, "an undefined signal is normal outside streaming (§A4)");

    assert.equal(result, undefined);
    assert.equal(ctx.confirmCalls.length, 1);
    assert.equal(typeof ctx.confirmCalls[0]?.opts?.timeout, "number");
    assert.equal(ctx.confirmCalls[0]?.opts?.signal, undefined);
  } finally {
    await api.close();
  }
});

test("HOOK-03 a confirm implementation that rejects declines instead of propagating", async () => {
  const api = await startMockApi({ mode: "ask" });
  const ctx = createFakeCtx();
  ctx.ui.confirm = async () => {
    throw new Error("ui exploded");
  };
  try {
    let result: { block?: boolean; reason?: string } | undefined;
    await assert.doesNotReject(async () => {
      result = await decideToolCall(
        createFakeToolCallEvent("bash", { command: "rm -rf /tmp/x" }),
        ctx,
        depsFor(api),
      );
    }, "a throwing UI must never become a thrown handler (§F1)");

    assert.deepStrictEqual(result, {
      block: true,
      reason: "Declined by user (Unbound policy)",
    });
  } finally {
    await api.close();
  }
});
