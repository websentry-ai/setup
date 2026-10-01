// HOOK-04 — a user-typed `!cmd` / `!!cmd` goes through the same policy path as a model tool call,
// and a deny comes back as pi's OWN four-key `BashResult`.
//
// Why this file is shaped around one object's exact keys: `UserBashEventResult` has no `block`
// field. It is `{operations} | {result: BashResult}`, and `runner.js:51-74` validates the return at
// runtime — `"exitCode" in resultRecord` is a **key-presence** check, both arms present is invalid,
// and a failure makes the runner throw (`runner.js:876-878`). A thrown `user_bash` handler is not
// fail-open and not even loud: `emitUserBash` rethrows, `interactive-mode.js:5656-5666` catches and
// returns **without running the command**, and `rpc-mode.js:442` has no catch at all. So the command
// silently does not run, nothing is rendered, and the user is left with an extension diagnostic.
// That is the failure mode every case below exists to make impossible.
//
// `isValidUserBashResult` re-implements the runner's validator from the transcribed source rather
// than importing anything, so the shape is asserted against pi's rule and not against our own.

import assert from "node:assert/strict";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createApiClient } from "../../core/src/client.ts";
import { TURNLOG_PATH } from "../../core/src/constants.ts";
import { turnStore } from "../../core/src/turn.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import type { PolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import type { DecideDeps } from "../src/decide.ts";
import { createExtension } from "../src/index.ts";
import { decideUserBash } from "../src/userBash.ts";
import {
  createFakeAgentEndEvent,
  createFakeClock,
  createFakeCtx,
  createFakeInputEvent,
  createFakeUserBashEvent,
} from "./helpers/fakeCtx.ts";
import type { FakeCtxOptions } from "./helpers/fakeCtx.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";

const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";

// The locked literals, spelled out rather than imported: a typo in `constants.ts` must fail here
// instead of silently retuning the assertion.
const DENY_PREFIX = "Blocked by Unbound policy: ";
const GENERIC_DENY = "Blocked by Unbound policy.";
const DECLINED = "Declined by user (Unbound policy)";
const NO_UI =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
const UNAVAILABLE = "Unbound policy engine unavailable — please retry";

/** `/^ubash_[0-9a-f]{20}$/`, built without a literal so the prefix constant is the only source. */
const UBASH_ID = new RegExp("^ubash_[0-9a-f]{20}$");

function depsFor(api: MockApi, state: PolicyState = createPolicyState()): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
  return {
    checker: createPolicyChecker({
      client,
      state,
      telemetry: createTelemetry({ client, apiKey: TEST_KEY }),
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
    state,
  };
}

function pretoolBodies(api: MockApi): Record<string, unknown>[] {
  return api.requests
    .filter((r) => r.path === PRETOOL_PATH)
    .map((r) => r.body as Record<string, unknown>);
}

/**
 * `isUserBashEventResult`, transcribed from `PI/dist/core/extensions/runner.js:51-74`.
 *
 * Deliberately a copy: if our result ever stopped satisfying pi's real rule, importing pi's runtime
 * guard would be impossible (it is a value export — it would inline the whole agent), and asserting
 * against our own helper would be circular. The line reference above is the source of truth.
 */
function isValidUserBashResult(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as { operations?: unknown; result?: unknown };
  const hasOperations = candidate.operations !== undefined;
  const hasResult = candidate.result !== undefined;
  // Exactly one arm. Both, or neither, is invalid.
  if (hasOperations === hasResult) return false;
  if (hasOperations) return false;
  const result = candidate.result;
  if (typeof result !== "object" || result === null) return false;
  const r = result as Record<string, unknown>;
  return (
    typeof r.output === "string" &&
    "exitCode" in r &&
    (r.exitCode === undefined || typeof r.exitCode === "number") &&
    typeof r.cancelled === "boolean" &&
    typeof r.truncated === "boolean" &&
    (r.fullOutputPath === undefined || typeof r.fullOutputPath === "string")
  );
}

/** The output string of a deny result, or `undefined` when the handler allowed the command. */
function outputOf(value: unknown): string | undefined {
  return (value as { result?: { output?: string } } | undefined)?.result?.output;
}

interface RunOptions {
  command?: string;
  cwd?: string;
  ctx?: Partial<FakeCtxOptions>;
  /** Extra calls made before the asserted one, used to prime `failBlock`. */
  warmups?: number;
}

async function run(
  mode: MockMode,
  opts: RunOptions = {},
): Promise<{
  result: unknown;
  bodies: Record<string, unknown>[];
  ctx: ReturnType<typeof createFakeCtx>;
}> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx(opts.ctx);
  const deps = depsFor(api);
  try {
    for (let i = 0; i < (opts.warmups ?? 0); i += 1) {
      await decideUserBash(createFakeUserBashEvent("echo warmup"), ctx, deps);
    }
    const result = await decideUserBash(
      createFakeUserBashEvent(opts.command ?? "cat /etc/shadow", { cwd: opts.cwd ?? "/tmp/fake-cwd" }),
      ctx,
      deps,
    );
    return { result, bodies: pretoolBodies(api), ctx };
  } finally {
    await api.close();
  }
}

test("HOOK-04 allow returns undefined, so pi runs the command itself", async () => {
  const { result, bodies, ctx } = await run("allow");

  assert.equal(result, undefined, "undefined is the only 'no opinion' pi understands");
  assert.equal(bodies.length, 1, "and it was genuinely checked");
  assert.equal(ctx.notifyCalls.length, 0, "an allow is silent");
});

test("HOOK-04 deny returns the exact four-key BashResult, with no operations arm", async () => {
  const { result, ctx } = await run("deny");

  assert.deepStrictEqual(result, {
    result: {
      output: `${DENY_PREFIX}Reading secrets is blocked.`,
      exitCode: 1,
      cancelled: false,
      truncated: false,
    },
  });
  assert.equal(Object.hasOwn(result as object, "block"), false, "UserBashEventResult has no block");
  assert.equal(Object.hasOwn(result as object, "operations"), false, "both arms is invalid");
  const inner = (result as { result: Record<string, unknown> }).result;
  assert.equal("exitCode" in inner, true, "runner.js:68 tests key PRESENCE, not the value");
  assert.deepStrictEqual(
    Object.keys(inner).sort(),
    ["cancelled", "exitCode", "output", "truncated"],
    "exactly the four required keys, nothing else",
  );

  assert.equal(ctx.notifyCalls.length, 1);
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: "Reading secrets is blocked.",
    type: "error",
  });
});

test("HOOK-04 the returned object satisfies pi's own runtime validator", async () => {
  for (const mode of ["deny", "denyNoReason"] as MockMode[]) {
    const { result } = await run(mode);
    assert.equal(isValidUserBashResult(result), true, `${mode} produced a shape the runner rejects`);
  }
});

test("HOOK-04 a deny with no reason falls back to the generic string, never undefined", async () => {
  const { result } = await run("denyNoReason");

  assert.equal(outputOf(result), GENERIC_DENY);
  assert.equal(outputOf(result)?.includes("undefined"), false, "no stringified undefined");
});

test("HOOK-04 confirm with a UI asks exactly once, with a bounded dialog", async () => {
  const { result, ctx } = await run("ask", { ctx: { hasUI: true, confirmResult: true } });

  assert.equal(result, undefined, "an accepted confirmation runs the command");
  assert.equal(ctx.confirmCalls.length, 1, "exactly one dialog");
  const opts = ctx.confirmCalls[0]?.opts;
  assert.equal(typeof opts?.timeout, "number", "an unbounded dialog would hang the TUI");
  assert.notEqual(opts?.signal, undefined, "and it must be abortable");
});

test("HOOK-04 confirm: the reason is notified once, and the dialog only asks", async () => {
  // The same de-duplication as the `tool_call` path — `user_bash` mirrored the composition, so it
  // rendered the reason twice in exactly the same way.
  const { ctx } = await run("ask", { ctx: { hasUI: true, confirmResult: true } });

  assert.deepStrictEqual(ctx.notifyCalls, [{ message: "Unusual command.", type: "warning" }]);
  assert.equal(ctx.confirmCalls[0]?.title, "Unbound policy");
  assert.equal(ctx.confirmCalls[0]?.message, "Run this command?");
});

test("HOOK-04 a declined confirmation becomes a BashResult carrying the declined reason", async () => {
  const { result, ctx } = await run("ask", { ctx: { hasUI: true, confirmResult: false } });

  assert.equal(isValidUserBashResult(result), true);
  assert.equal(outputOf(result), DECLINED);
  assert.equal(ctx.confirmCalls.length, 1);
});

test("HOOK-04 confirm without a UI blocks with the headless reason and never asks", async () => {
  const { result, ctx } = await run("ask", { ctx: { hasUI: false } });

  assert.equal(isValidUserBashResult(result), true);
  assert.equal(outputOf(result), NO_UI);
  assert.equal(ctx.confirmCalls.length, 0, "there is nobody to ask");
});

test("HOOK-04 approval_required is treated as a confirmation, not as a silent allow", async () => {
  const { result } = await run("approval", { ctx: { hasUI: true, confirmResult: false } });

  assert.equal(outputOf(result), DECLINED);
});

test("HOOK-04 a fail-closed org gets the unavailable reason as a BashResult, not a throw", async () => {
  // `failBlock` answers the warmup with `policy_check_failure_action: 'block'`, then hangs.
  const { result } = await run("failBlock", { warmups: 1 });

  assert.equal(isValidUserBashResult(result), true, "even fail-closed must return a valid shape");
  assert.equal(outputOf(result), UNAVAILABLE);
});

test("HOOK-04 a blank or whitespace-only command costs zero HTTP", async () => {
  for (const command of ["", "   ", "\t\n"]) {
    const { result, bodies } = await run("deny", { command });
    assert.equal(result, undefined, `'${command}' is nothing to evaluate`);
    assert.equal(bodies.length, 0, "no round trip at all");
  }
});

test("HOOK-04 the payload carries tool_name bash, the typed command, and the EVENT's cwd", async () => {
  const { bodies } = await run("allow", { command: "rm -rf /srv", cwd: "/srv/worktree", ctx: { cwd: "/somewhere/else" } });

  const data = bodies[0]?.pre_tool_use_data as {
    tool_name?: string;
    command?: string;
    tool_use_id?: string;
    metadata?: Record<string, unknown>;
  };
  assert.equal(data.tool_name, "bash", "a user-typed command is a bash command");
  assert.equal(data.command, "rm -rf /srv", "verbatim");
  assert.equal(
    data.metadata?.cwd,
    "/srv/worktree",
    "UserBashEvent carries its own cwd; ctx.cwd is the wrong one to send",
  );
  // `toolInput` is `{}` by construction, so the allowlist has nothing to forward and cannot leak.
  assert.deepStrictEqual(data.metadata?.tool_input, {});
});

test("HOOK-04 the recorded decision carries the typed command as its tool_input", async () => {
  // A `!cmd` has no model-produced input at all, so `{}` in means the capped `command` is the only
  // key out — and it is the entire content of the call. Without it the audit row said "bash" and
  // nothing else about what the developer actually ran.
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  const entries: { tool_name: string; decision: string; tool_input?: Record<string, unknown> }[] = [];
  try {
    await decideUserBash(createFakeUserBashEvent("echo hi"), ctx, {
      ...depsFor(api),
      onDecision: (entry) => entries.push(entry),
    });

    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.tool_name, "bash");
    assert.deepStrictEqual(entries[0]?.tool_input, { command: "echo hi" });
  } finally {
    await api.close();
  }
});

test("HOOK-04 tool_use_id is a generated ubash_ id, and two calls never share one", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  const deps = depsFor(api);
  try {
    await decideUserBash(createFakeUserBashEvent("echo one"), ctx, deps);
    await decideUserBash(createFakeUserBashEvent("echo two"), ctx, deps);

    const ids = pretoolBodies(api).map(
      (b) => (b.pre_tool_use_data as { tool_use_id?: string }).tool_use_id,
    );
    assert.equal(ids.length, 2);
    for (const id of ids) {
      assert.ok(id !== undefined && UBASH_ID.test(id), `id ${String(id)} is not a ubash_ id`);
    }
    assert.notEqual(ids[0], ids[1], "pi gives the event no id, so a shared one would merge two calls");
  } finally {
    await api.close();
  }
});

test("HOOK-04 user_bash is never cache-skipped, even with an empty fresh tools_to_check", async () => {
  const clock = createFakeClock();
  const state = createPolicyState();
  state.recordSuccess(
    { decision: "allow", policy_check_failure_action: "allow", tools_to_check: [] },
    clock.now(),
  );

  const api = await startMockApi({ mode: "deny" });
  const ctx = createFakeCtx();
  try {
    const result = await decideUserBash(
      createFakeUserBashEvent("cat /etc/shadow"),
      ctx,
      { ...depsFor(api, state), now: clock.now },
    );

    assert.equal(outputOf(result), `${DENY_PREFIX}Reading secrets is blocked.`);
    assert.equal(pretoolBodies(api).length, 1, "a shell command is never answerable from a tool list");
  } finally {
    await api.close();
  }
});

test("HOOK-04 no API key: the registered handler is inert, with zero HTTP and no result", async () => {
  const api = await startMockApi({ mode: "deny" });
  const home = createFakeHome({});
  try {
    const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
    const stub = { on: (event: string, handler: (e: unknown, c: unknown) => unknown) => {
      handlers.set(event, handler);
      return () => {};
    } };
    await createExtension({
      env: { UNBOUND_GATEWAY_URL: api.url },
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
    })(stub as unknown as ExtensionAPI);

    const handler = handlers.get("user_bash");
    assert.ok(handler !== undefined, "user_bash must be registered");
    const result = await handler(createFakeUserBashEvent("cat /etc/shadow"), createFakeCtx());

    assert.equal(result, undefined, "no key means no opinion, never a block");
    assert.equal(api.requests.length, 0);
  } finally {
    home.cleanup();
    await api.close();
  }
});

// --- A `!cmd` is its own turn log --------------------------------------------------------------
//
// pi fires no `agent_end` for a typed command. It used to be recorded into the shared turn store,
// where the NEXT agent turn posted it under that turn's prompt — a row attributing the developer's
// own command to a conversation it had nothing to do with. The contract is now: one standalone
// one-call `/v1/hooks/pi` POST, right after the decision, and the shared store untouched.

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

interface TurnLogBodyLike {
  conversation_id?: string;
  messages?: { content?: unknown; tool_use?: Record<string, unknown>[] }[];
}

async function keyedExtension(api: MockApi): Promise<{ handlers: Map<string, AnyHandler>; cleanup(): void }> {
  const home = createFakeHome({});
  const handlers = new Map<string, AnyHandler>();
  const stub = {
    on: (event: string, handler: AnyHandler) => {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension({
    env: { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url },
    homeDir: home.homeDir,
    entrypoint: "pi/0.87.1",
    heartbeatGate: { shouldSend: () => false, markSent: () => {} },
  })(stub as unknown as ExtensionAPI);
  return { handlers, cleanup: () => home.cleanup() };
}

function turnLogBodies(api: MockApi): TurnLogBodyLike[] {
  return api.requests.filter((r) => r.path === TURNLOG_PATH).map((r) => r.body as TurnLogBodyLike);
}

test("a !cmd posts exactly one one-call turn log, without waiting for agent_end", async () => {
  turnStore.take();
  const api = await startMockApi({ mode: "allow" });
  const f = await keyedExtension(api);
  try {
    const ctx = createFakeCtx({ sessionId: "sess-ubash-1" });
    const result = await f.handlers.get("user_bash")?.(createFakeUserBashEvent("echo hi"), ctx);
    assert.equal(result, undefined, "an allow still hands execution back to pi");
    await sleep(60);

    const logs = turnLogBodies(api);
    assert.equal(logs.length, 1, "posted immediately — no agent_end fired");
    const body = logs[0] as TurnLogBodyLike;
    assert.equal(body.conversation_id, "sess-ubash-1");
    assert.equal(body.messages?.[0]?.content, "", "a !cmd has no prompt, and none is invented");
    const uses = body.messages?.[1]?.tool_use ?? [];
    assert.equal(uses.length, 1, "one call");
    assert.equal(uses[0]?.tool_name, "bash");
    assert.ok(UBASH_ID.test(String(uses[0]?.tool_use_id)), "the generated ubash_ id");
    assert.deepStrictEqual(uses[0]?.tool_input, { command: "echo hi" });

    assert.deepStrictEqual(
      turnStore.snapshot(),
      { tool_calls: [], results: [] },
      "the shared turn store is untouched by a !cmd",
    );
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a !cmd is never merged into the next agent turn's log", async () => {
  turnStore.take();
  const api = await startMockApi({ mode: "allow" });
  const f = await keyedExtension(api);
  try {
    const ctx = createFakeCtx({ sessionId: "sess-ubash-2" });
    await f.handlers.get("user_bash")?.(createFakeUserBashEvent("echo standalone"), ctx);
    await f.handlers.get("input")?.(createFakeInputEvent("now a real prompt"), ctx);
    f.handlers.get("agent_end")?.(createFakeAgentEndEvent([]), ctx);
    await sleep(60);

    const logs = turnLogBodies(api);
    assert.equal(logs.length, 2, "the !cmd row, then the agent turn");
    const ubashId = String(logs[0]?.messages?.[1]?.tool_use?.[0]?.tool_use_id);
    assert.ok(UBASH_ID.test(ubashId));
    const agentTurn = logs[1] as TurnLogBodyLike;
    assert.equal(agentTurn.messages?.[0]?.content, "now a real prompt");
    assert.deepStrictEqual(agentTurn.messages?.[1]?.tool_use, [], "the agent turn made no calls");
    assert.equal(JSON.stringify(agentTurn).includes(ubashId), false, "and does not carry the !cmd");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a denied or confirmed !cmd returns the same result as before, and is still posted once", async () => {
  turnStore.take();
  for (const [mode, confirmResult] of [
    ["deny", true],
    ["ask", false],
  ] as const) {
    const api = await startMockApi({ mode });
    const f = await keyedExtension(api);
    try {
      const ctx = createFakeCtx({ sessionId: "sess-ubash-3", hasUI: true, confirmResult });
      const result = await f.handlers.get("user_bash")?.(createFakeUserBashEvent("cat /etc/shadow"), ctx);
      assert.equal(isValidUserBashResult(result), true, `${mode}: still pi's own BashResult`);
      assert.equal(
        outputOf(result),
        mode === "deny" ? `${DENY_PREFIX}Reading secrets is blocked.` : DECLINED,
      );
      await sleep(60);
      const logs = turnLogBodies(api);
      // The turn-log wire shape carries no `decision` key (the gateway's block row is the record of
      // the verdict); what matters here is that the row exists, once, for the blocked command too.
      assert.equal(logs.length, 1, `${mode}: one row`);
      assert.ok(UBASH_ID.test(String(logs[0]?.messages?.[1]?.tool_use?.[0]?.tool_use_id)));
    } finally {
      f.cleanup();
      await api.close();
    }
  }
});

test("no key: a !cmd posts nothing at all", async () => {
  const api = await startMockApi({ mode: "allow" });
  const home = createFakeHome({});
  try {
    const handlers = new Map<string, AnyHandler>();
    const stub = { on: (event: string, handler: AnyHandler) => {
      handlers.set(event, handler);
      return () => {};
    } };
    await createExtension({
      env: { UNBOUND_GATEWAY_URL: api.url },
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
      heartbeatGate: { shouldSend: () => false, markSent: () => {} },
    })(stub as unknown as ExtensionAPI);
    await handlers.get("user_bash")?.(createFakeUserBashEvent("echo hi"), createFakeCtx());
    await sleep(60);
    assert.equal(api.requests.length, 0, "no pretool, no turn log");
  } finally {
    home.cleanup();
    await api.close();
  }
});
