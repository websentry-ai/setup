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
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TIMEOUT_MS = 50;

const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";

function depsFor(api: MockApi): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS, profile: PI_PROFILE });
  return {
    checker: createPolicyChecker({
      client,
      state: createPolicyState(),
      telemetry: createTelemetry({ client, apiKey: TEST_KEY, profile: PI_PROFILE }),
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
  assert.equal(call.message, "Run this command?", "the dialog asks, and only asks");
  assert.equal(typeof call.opts?.timeout, "number", "a confirm without a timeout can hang (§F5)");
  assert.ok((call.opts?.timeout ?? 0) > 0, "the timeout must be positive");
  assert.equal(call.opts?.signal, ctx.signal, "the turn's abort signal is forwarded");
});

test("HOOK-03 ask: the reason is rendered once, by the notification and not by the dialog", async () => {
  // The reason used to be composed into the confirm body as well as raised as a warning, so pi
  // rendered the same paragraph twice — once in the yellow warning box, once inside the overlay. The
  // notice is the channel that keeps it: it is also what survives after the dialog closes.
  const { ctx } = await run("ask", { confirmResult: true });

  assert.equal(ctx.notifyCalls.length, 1, "exactly one notification");
  assert.deepStrictEqual(ctx.notifyCalls[0], { message: "Unusual command.", type: "warning" });

  assert.equal(ctx.confirmCalls.length, 1);
  assert.equal(
    ctx.confirmCalls[0]?.message.includes("Unusual command."),
    false,
    `the dialog body repeats the reason: ${String(ctx.confirmCalls[0]?.message)}`,
  );
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
  assert.equal(accepted.ctx.confirmCalls[0]?.message, "Run this command?");
  // The reason still reaches the developer — through the notification, exactly once.
  assert.deepStrictEqual(accepted.ctx.notifyCalls, [
    { message: "Needs admin approval.", type: "warning" },
  ]);

  const declined = await run("approval", { confirmResult: false });
  assert.deepStrictEqual(declined.result, {
    block: true,
    reason: "Declined by user (Unbound policy)",
  });
});

test("HOOK-03 headless: ask blocks with the no-UI reason and never opens a dialog", async () => {
  // Unchanged by the de-duplication above: with nobody to ask there is no dialog to strip a reason
  // from, and the block reason is the only channel left.
  const { result, ctx } = await run("ask", { hasUI: false, mode: "json" });

  assert.deepStrictEqual(result, { block: true, reason: NO_UI_REASON });
  assert.equal(ctx.confirmCalls.length, 0, "there is nobody to ask");
});

test("HOOK-03 deny still notifies the reason exactly once, as an error", async () => {
  // The deny path opens no dialog, so its notification is the whole of the developer's feedback and
  // must not be touched by the confirm-path change.
  const { result, ctx } = await run("deny");

  assert.equal(result?.block, true);
  assert.equal(ctx.confirmCalls.length, 0, "a deny is not a question");
  assert.deepStrictEqual(ctx.notifyCalls, [
    { message: "Reading secrets is blocked.", type: "error" },
  ]);
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
