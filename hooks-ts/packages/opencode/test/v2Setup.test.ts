// The active v2 `setup` entry (14-04): one process-wide runtime shared across module evaluations
// (14-SPIKES V2-12: setup runs once per directory, the module is re-evaluated per directory, and
// `globalThis` is shared), the 14-03 enforcement handlers and the 14-04 recording handlers
// registered once per directory, one `v2_status` per process, fail-open registration, the slot's
// tamper rule (keep enforcing, report), and the cleanup the host runs on location shutdown.

import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
    "tools:enforce/ask:native/mcp:enforce/prompt:block/recording:full/identity:provider/shell:enforce",
  );
});

test("the loader smoke expects exactly the shipped v2_status detail", () => {
  const smoke = readFileSync(fileURLToPath(new URL("../../../scripts/opencode-loader-smoke.mjs", import.meta.url)), "utf8");
  const match = /export const EXPECTED_V2_STATUS =\s*"([^"]+)";/.exec(smoke);
  assert.ok(match !== null, "EXPECTED_V2_STATUS is declared in the smoke");
  assert.equal(match[1], v2StatusDetail(V2_CAPABILITIES));
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

/**
 * A host that keeps every registration until its handle is disposed and fires ALL live callbacks of
 * a hook, like a host that does not drop a location's hooks on its own (WR-02).
 */
function keepingHost(directory: string): {
  ctx: Record<string, unknown>;
  fire(hook: string, event: unknown): Promise<void>;
  live(hook: string): number;
} {
  const live = new Map<string, Set<Handler>>();
  const domain = (name: string) => ({
    hook: async (hook: string, cb: Handler) => {
      const key = `${name}.${hook}`;
      const set = live.get(key) ?? new Set<Handler>();
      live.set(key, set);
      set.add(cb);
      return {
        dispose: async () => {
          set.delete(cb);
        },
      };
    },
  });
  const ctx: Record<string, unknown> = {
    app: { name: "cli", version: "2.0.24", channel: "latest" },
    location: { directory },
    tool: domain("tool"),
    permission: domain("permission"),
    session: { ...domain("session"), get: async () => ({ id: "s" }) },
    shell: domain("shell"),
    mcp: { list: async () => ({ data: [] }) },
    event: { subscribe: () => ({ async *[Symbol.asyncIterator]() {} }) },
  };
  return {
    ctx,
    async fire(hook: string, event: unknown): Promise<void> {
      for (const cb of [...(live.get(hook) ?? [])]) await cb(event);
    },
    live: (hook: string) => live.get(hook)?.size ?? 0,
  };
}

test("WR-02: cleanup disposes every hook; setup, cleanup, setup for one directory checks each call once", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const host = keepingHost("/repo");
    const first = await setup(host.ctx);
    await tick(5);
    for (const hook of ALL_HOOKS) assert.equal(host.live(hook), 1, hook);
    await (first as () => Promise<void>)();
    await tick(5);
    for (const hook of ALL_HOOKS) assert.equal(host.live(hook), 0, `${hook} disposed`);
    // A second cleanup call is a no-op.
    await (first as () => Promise<void>)();

    // The location comes back: one fresh set, not two.
    const second = await setup(host.ctx);
    assert.equal(typeof second, "function");
    // And a repeated setup without a cleanup registers nothing more.
    assert.equal(await setup(host.ctx), undefined);
    await tick(5);
    for (const hook of ALL_HOOKS) assert.equal(host.live(hook), 1, `${hook} once`);

    mock.setMode("deny");
    await host.fire("tool.execute.before", { tool: "shell", sessionID: "s1", agent: "b", messageID: "m", id: "c1", input: { command: "cat .env" } });
    const evaluate: Record<string, unknown> = { sessionID: "s1", action: "shell", resources: ["cat .env"], source: { type: "tool", messageID: "m", id: "c1" }, effect: "allow" };
    await host.fire("permission.evaluate", evaluate);
    assert.equal(evaluate.effect, "deny");
    assert.equal(pretoolRequests(mock).length, 1, "exactly one check per call");
  } finally {
    t.cleanup();
  }
});

test("WR-02: a registration that resolves after the cleanup is disposed as it arrives", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const host = keepingHost("/repo");
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tool = host.ctx.tool as { hook: (hook: string, cb: Handler) => Promise<unknown> };
    const slowHook = tool.hook;
    host.ctx.tool = {
      hook: async (hook: string, cb: Handler) => {
        await gate;
        return slowHook(hook, cb);
      },
    };
    const cleanup = await setup(host.ctx);
    await (cleanup as () => Promise<void>)();
    release?.();
    await tick(20);
    assert.equal(host.live("tool.execute.before"), 0);
    assert.equal(host.live("tool.execute.after"), 0);
  } finally {
    t.cleanup();
  }
});

/**
 * One process hosting several directories. As observed on 2.0.24, `event.subscribe()` delivers
 * EVERY location's events to every registration. `globalHooks` simulates a host that would also
 * fire one call's hooks in every registration (with the same input object, or a copy per callback).
 */
function sharedHost(): {
  ctxFor(directory: string): Record<string, unknown>;
  fire(hook: string, event: Record<string, unknown>, opts?: { copy?: boolean }): Promise<string | undefined>;
  publish(event: unknown): void;
} {
  const live = new Map<string, Set<Handler>>();
  const subscribers = new Set<(event: unknown) => void>();
  const domain = (name: string) => ({
    hook: async (hook: string, cb: Handler) => {
      const key = `${name}.${hook}`;
      const set = live.get(key) ?? new Set<Handler>();
      live.set(key, set);
      set.add(cb);
      return { dispose: async () => void set.delete(cb) };
    },
  });
  return {
    ctxFor(directory: string) {
      return {
        app: { name: "cli", version: "2.0.24", channel: "latest" },
        location: { directory },
        tool: domain("tool"),
        permission: domain("permission"),
        session: { ...domain("session"), get: async (i: { sessionID: string }) => ({ id: i.sessionID }) },
        shell: domain("shell"),
        mcp: { list: async () => ({ data: [] }) },
        event: {
          subscribe: (options?: { signal?: AbortSignal }) => {
            const queue: unknown[] = [];
            let wake: (() => void) | undefined;
            const push = (e: unknown): void => {
              queue.push(e);
              wake?.();
            };
            subscribers.add(push);
            options?.signal?.addEventListener("abort", () => {
              subscribers.delete(push);
              wake?.();
            });
            return {
              async *[Symbol.asyncIterator]() {
                while (options?.signal?.aborted !== true) {
                  if (queue.length === 0) await new Promise<void>((r) => (wake = r));
                  while (queue.length > 0) yield queue.shift();
                }
              },
            };
          },
        },
      };
    },
    async fire(hook, event, opts = {}) {
      try {
        for (const cb of [...(live.get(hook) ?? [])]) await cb(opts.copy === true ? structuredClone(event) : event);
        return undefined;
      } catch (err) {
        return (err as Error).message;
      }
    },
    publish(event) {
      for (const push of [...subscribers]) push(event);
    },
  };
}

function heartbeats(): number {
  return pretoolRequests(mock).filter((r) => (r.body as { event_name?: string }).event_name === "session_start").length;
}

test("WR-03: with two directories every event reaches both registrations, and each is handled by one", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const host = sharedHost();
    await setup(host.ctxFor("/proj"));
    await setup(host.ctxFor("/proj2"));
    await tick(5);
    // A root session in /proj2: delivered to both subscriptions (2.0.24), one heartbeat.
    host.publish({ id: "evt_1", type: "session.created", location: { directory: "/proj2" }, data: { sessionID: "ses_b", location: { directory: "/proj2" }, version: "2.0.24" } });
    // An event with no location and an unknown session: handled by exactly one registration.
    host.publish({ id: "evt_2", type: "session.created", data: { sessionID: "ses_c", version: "2.0.24" } });
    assert.ok(await waitFor(() => heartbeats() >= 1));
    await tick(100);
    // evt_1 → /proj2 (its owner) once; evt_2 → whichever single registration claimed it.
    const dirs = pretoolRequests(mock)
      .map((r) => (r.body as { pre_tool_use_data?: { metadata?: { cwd?: string } } }).pre_tool_use_data?.metadata?.cwd)
      .filter((d) => d !== undefined);
    assert.equal(dirs.filter((d) => d === "/proj2").length, 1);
    assert.ok(dirs.length <= 2, JSON.stringify(dirs));
  } finally {
    t.cleanup();
  }
});

for (const copy of [false, true]) {
  test(`WR-03: hooks fired in every registration (${copy ? "a copy each" : "same object"}) never raise on a model call; ${copy ? "no false block" : "checked once"}`, async () => {
    resetMock();
    const t = makeDeps(mock);
    try {
      const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
      const host = sharedHost();
      await setup(host.ctxFor("/proj"));
      await setup(host.ctxFor("/proj2"));
      await tick(5);
      mock.setMode("allow");
      const before = { tool: "shell", sessionID: "s1", agent: "b", messageID: "m", id: "c1", input: { command: "make test" } };
      assert.equal(await host.fire("tool.execute.before", before, { copy }), undefined);
      // The model's own spawn reaches both user-shell handlers: neither checks it as a user command.
      const spawn = { command: "make test", cwd: "/proj", timeout: 120_000, shell: "/bin/zsh", env: {} };
      mock.setMode("deny");
      assert.equal(await host.fire("shell.create.before", spawn, { copy }), undefined, "never raised");
      const checks = pretoolRequests(mock).filter((r) => (r.body as { event_name?: string }).event_name === "tool_use");
      assert.equal(checks.length, copy ? 2 : 1, copy ? "a copy per callback cannot be told apart: decided twice, never blocked" : "decided once");
      // A real user command is still checked and raised.
      const user = { command: "cat .env", cwd: "/proj2", timeout: 0, shell: "/bin/zsh", env: {} };
      assert.ok((await host.fire("shell.create.before", user, { copy }))?.startsWith("Blocked by Unbound policy"));
    } finally {
      t.cleanup();
    }
  });
}

test("IN-06: with no key at the first setup, v2_status is sent once a key appears", async () => {
  resetMock();
  let clock = 5_000_000;
  const t = makeDeps(mock, { withKey: false, now: () => clock });
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-setup-test") });
    const a = fakeCtx("/repo");
    await setup(a.ctx);
    await tick(50);
    assert.equal(signalsOf(mock, SIGNAL_V2_STATUS).length, 0, "nothing can be sent without a key");
    // The key is installed while the process runs; the runtime looks again after its retry window.
    (t.deps.env as NodeJS.ProcessEnv).UNBOUND_OPENCODE_API_KEY = "test-key-added-later";
    clock += 31_000;
    await a.handlers.get("tool.execute.before")?.({ tool: "read", sessionID: "s1", agent: "b", messageID: "m", id: "c1", input: { path: "a" } });
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_V2_STATUS).length === 1));
    await a.handlers.get("tool.execute.before")?.({ tool: "read", sessionID: "s1", agent: "b", messageID: "m", id: "c2", input: { path: "a" } });
    await setup(fakeCtx("/other").ctx);
    await tick(100);
    assert.equal(signalsOf(mock, SIGNAL_V2_STATUS).length, 1, "still once per process");
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
    assert.ok((message ?? "").includes("tools:audit/"), message);
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

test("IN-07: another genuine build in the v2 slot keeps enforcing and reports duplicate_load other_build", async () => {
  resetMock();
  const t = makeDeps(mock);
  const sentinelKey = Symbol("v2-setup-test");
  try {
    // The older build's holder, as its own setup left it (module re-evaluated after an upgrade).
    await createSetupV2({ ...t.deps, sentinelKey, buildToken: "0123456789abcdef0123456789abcdef" })(fakeCtx("/old").ctx);
    const a = fakeCtx("/repo");
    assert.equal(typeof (await createSetupV2({ ...t.deps, sentinelKey, buildToken: "fedcba9876543210fedcba9876543210" })(a.ctx)), "function");
    await tick(5);
    assert.equal(a.handlers.size, ALL_HOOKS.length, "registered: this build enforces too");
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length === 1));
    const body = signalsOf(mock, SIGNAL_DUPLICATE_LOAD)[0]?.body as { errors?: Array<{ message?: string }> };
    assert.ok((body.errors?.[0]?.message ?? "").includes("other_build"), body.errors?.[0]?.message);
    await tick(50);
    assert.equal(signalsOf(mock, SIGNAL_SENTINEL_TAMPERED).length, 0);
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
    // WR-05: no auth mode on v2, and the provider id never leaves the device (no serial in tests).
    for (const r of pretoolRequests(mock)) {
      const body = r.body as { account_identity?: Record<string, unknown> };
      assert.equal(body.account_identity, undefined);
      assert.equal(JSON.stringify(body).includes('"auth_mode"'), false);
    }
  } finally {
    t.cleanup();
  }
});
