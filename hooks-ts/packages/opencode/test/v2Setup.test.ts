// The active v2 `setup` entry (14-04): one process-wide runtime shared across module evaluations
// (14-SPIKES V2-12: setup runs once per directory, the module is re-evaluated per directory, and
// `globalThis` is shared), the 14-03 enforcement handlers and the 14-04 recording handlers
// registered once per directory, one `v2_status` per process, fail-open registration, the slot's
// tamper rule (keep enforcing, report), and the cleanup the host runs on location shutdown.

import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";

import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import {
  SIGNAL_API_FAMILY_INACTIVE,
  SIGNAL_DUPLICATE_LOAD,
  SIGNAL_INIT_DEGRADED,
  SIGNAL_SENTINEL_TAMPERED,
  SIGNAL_V2_NOT_ENFORCING,
  SIGNAL_V2_STATUS,
  V2_CAPABILITIES,
} from "../src/constants.ts";
import { createSetupV2, v2StatusDetail } from "../src/v2.ts";
import { makeDeps, pretoolRequests, signalsOf, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

function resetMock(): void {
  mock.requests.length = 0;
  mock.setMode("allow");
  mock.setErrorsMode("ok");
}

type Handler = (event: unknown) => Promise<void> | void;

interface FakeCtx {
  ctx: Record<string, unknown>;
  handlers: Map<string, Handler>;
  subscriptions: () => number;
  aborted: () => boolean;
}

/** A v2 ctx with every domain the adapter uses; `toolHook` replaces `ctx.tool.hook`. */
function fakeCtx(directory: string, opts: { toolHook?: (...args: unknown[]) => unknown } = {}): FakeCtx {
  const handlers = new Map<string, Handler>();
  let subscribed = 0;
  let aborted = false;
  const domain = (name: string) => ({
    hook: async (hook: string, cb: Handler) => {
      handlers.set(`${name}.${hook}`, cb);
      return { dispose: async () => undefined };
    },
  });
  const ctx: Record<string, unknown> = {
    app: { name: "cli", version: "2.0.22", channel: "latest" },
    location: { directory, project: { id: "p", directory, canonical: directory } },
    tool: opts.toolHook === undefined ? domain("tool") : { hook: opts.toolHook },
    permission: domain("permission"),
    session: { ...domain("session"), get: async () => ({ id: "s" }) },
    shell: domain("shell"),
    mcp: { list: async () => ({ data: [] }) },
    event: {
      subscribe: (options?: { signal?: AbortSignal }) => {
        subscribed += 1;
        options?.signal?.addEventListener("abort", () => {
          aborted = true;
        });
        return {
          async *[Symbol.asyncIterator]() {
            await new Promise<void>((resolve) => options?.signal?.addEventListener("abort", () => resolve()));
          },
        };
      },
    },
  };
  return { ctx, handlers, subscriptions: () => subscribed, aborted: () => aborted };
}

const ALL_HOOKS = [
  "tool.execute.before",
  "tool.execute.after",
  "permission.evaluate",
  "session.prompt",
  "session.model.request",
  "shell.create.before",
];

test("v2StatusDetail lists every capability", () => {
  assert.equal(
    v2StatusDetail(V2_CAPABILITIES),
    "tools=enforce;ask=native;mcp=enforce;prompt=block;recording=full;identity=provider;shell=enforce",
  );
});

test("setup on a v2 ctx registers every handler once per directory, without awaiting I/O", async () => {
  resetMock();
  const t = makeDeps(mock);
  const sentinelKey = Symbol("v2-setup-test");
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey });
    const a = fakeCtx("/repo");
    const cleanup = await setup(a.ctx);
    assert.equal(typeof cleanup, "function");
    assert.equal(mock.requests.length, 0, "nothing was sent before setup resolved");
    await tick(5);
    assert.deepEqual([...a.handlers.keys()].sort(), [...ALL_HOOKS].sort());
    assert.equal(a.subscriptions(), 1);

    // The same directory again, from this copy or a second module evaluation: nothing registered.
    const again = fakeCtx("/repo");
    assert.equal(await setup(again.ctx), undefined);
    assert.equal(await createSetupV2({ ...t.deps, sentinelKey })(again.ctx), undefined);
    await tick(5);
    assert.equal(again.handlers.size, 0);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length === 1));

    // Another directory, from a second module evaluation: registered, same process runtime.
    const b = fakeCtx("/other");
    assert.equal(typeof (await createSetupV2({ ...t.deps, sentinelKey })(b.ctx)), "function");
    await tick(5);
    assert.deepEqual([...b.handlers.keys()].sort(), [...ALL_HOOKS].sort());

    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_V2_STATUS).length === 1));
    await tick(100);
    assert.equal(signalsOf(mock, SIGNAL_V2_STATUS).length, 1, "one v2_status per process");
    assert.equal(signalsOf(mock, SIGNAL_API_FAMILY_INACTIVE).length, 0);
    assert.equal(signalsOf(mock, SIGNAL_V2_NOT_ENFORCING).length, 0, "nothing is audit-only");

    // The registered handlers enforce: a denied built-in call is denied at evaluate.
    mock.setMode("deny");
    await a.handlers.get("tool.execute.before")?.({ tool: "shell", sessionID: "s1", agent: "b", messageID: "m", id: "c1", input: { command: "cat .env" } });
    const evaluate: Record<string, unknown> = { sessionID: "s1", action: "shell", resources: ["cat .env"], source: { type: "tool", messageID: "m", id: "c1" }, effect: "allow" };
    await a.handlers.get("permission.evaluate")?.(evaluate);
    assert.equal(evaluate.effect, "deny");
    assert.equal(pretoolRequests(mock).length, 1);

    // Cleanup (location shutdown) stops recording and frees the directory for a later setup.
    await (cleanup as () => Promise<void>)();
    assert.equal(a.aborted(), true);
    const later = fakeCtx("/repo");
    assert.equal(typeof (await setup(later.ctx)), "function");
    await tick(5);
    assert.equal(later.handlers.size, ALL_HOOKS.length);
  } finally {
    t.cleanup();
  }
});

test("an audit-only tools capability also reports v2_not_enforcing once", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({
      ...t.deps,
      sentinelKey: Symbol("v2-setup-test"),
      capabilities: { ...V2_CAPABILITIES, tools: "audit" },
    });
    await setup(fakeCtx("/repo").ctx);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_V2_NOT_ENFORCING).length === 1));
    const message = (signalsOf(mock, SIGNAL_V2_STATUS)[0]?.body as { errors?: Array<{ message?: string }> }).errors?.[0]?.message;
    assert.match(message ?? "", /tools=audit/);
  } finally {
    t.cleanup();
  }
});

test("a registration fault leaves setup resolved, reports init_degraded once and registers nothing further", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const broken = fakeCtx("/repo", {
      toolHook: () => {
        throw new Error("host refused");
      },
    });
    const result = setup(broken.ctx);
    assert.ok(result instanceof Promise);
    await result;
    await tick(5);
    assert.equal(broken.subscriptions(), 0, "recording not registered after the fault");
    assert.equal(broken.handlers.has("permission.evaluate"), false);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_INIT_DEGRADED).length === 1));
    await tick(100);
    assert.equal(signalsOf(mock, SIGNAL_INIT_DEGRADED).length, 1);
  } finally {
    t.cleanup();
  }
});

test("a foreign value in the slot does not stop enforcement: registers and reports sentinel_tampered", async () => {
  resetMock();
  const t = makeDeps(mock);
  const sentinelKey = Symbol("v2-setup-test");
  try {
    (globalThis as Record<symbol, unknown>)[sentinelKey] = { module: "planted" };
    const setup = createSetupV2({ ...t.deps, sentinelKey });
    const a = fakeCtx("/repo");
    assert.equal(typeof (await setup(a.ctx)), "function");
    await tick(5);
    assert.equal(a.handlers.size, ALL_HOOKS.length);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_SENTINEL_TAMPERED).length === 1));
  } finally {
    t.cleanup();
  }
});

test("identity is provider-level: auth.json in the data dir is not read", async () => {
  resetMock();
  const t = makeDeps(mock);
  const dir = join(t.homeDir, ".local", "share", "opencode");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "auth.json"), JSON.stringify({ anthropic: { type: "oauth", access: "tok", refresh: "r", expires: Date.now() + 3_600_000 } }));
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const a = fakeCtx("/repo");
    await setup(a.ctx);
    await tick(5);
    await a.handlers.get("session.model.request")?.({ sessionID: "s1", agent: "b", model: { id: "m", providerID: "anthropic" }, kind: "primary", headers: {} });
    mock.setMode("allow");
    await a.handlers.get("tool.execute.before")?.({ tool: "shell", sessionID: "s1", agent: "b", messageID: "m", id: "c1", input: { command: "ls" } });
    // The second call carries the settled identity.
    await tick(20);
    await a.handlers.get("tool.execute.before")?.({ tool: "shell", sessionID: "s1", agent: "b", messageID: "m", id: "c2", input: { command: "ls" } });
    const last = pretoolRequests(mock).at(-1)?.body as { account_identity?: Record<string, unknown> };
    assert.deepEqual(last.account_identity, { auth_mode: "anthropic" });
  } finally {
    t.cleanup();
  }
});
