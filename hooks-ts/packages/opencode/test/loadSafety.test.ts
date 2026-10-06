// Load safety (RES-09, RES-10, Pitfalls 3, 15, 16): the plugin's shell before any decision logic.
//
//   * one default export `{ id, server, setup }` and nothing else;
//   * `server()` does no I/O and no awaited work, and never rejects; on an internal fault it
//     resolves a degraded allow-everything set that reports `init_degraded`;
//   * a second copy of the module in one process gets `{}` and reports `duplicate_load`, while one
//     copy serving several directories is not a duplicate;
//   * key, gateway and checker resolve lazily on the first hook, once per plugin copy;
//   * `config` snapshots MCP server names read-only; `dispose` releases the directory;
//   * the v2 `setup` entry is inert on a 1.18 host (whose embedded core host also calls it) and only
//     reports `api_family_inactive`, once, when it sees a real v2 ctx.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { NO_KEY_NOTICE } from "../../core/src/constants.ts";
import { createModuleToken, createServerPlugin } from "../src/plugin.ts";
import { createSetupV2 } from "../src/v2.ts";
import {
  SIGNAL_API_FAMILY_INACTIVE,
  SIGNAL_DUPLICATE_LOAD,
  SIGNAL_INIT_DEGRADED,
  SIGNAL_SENTINEL_TAMPERED,
} from "../src/constants.ts";
import {
  makeDeps,
  makeFakeInput,
  pretoolRequests,
  signalsOf,
  startOpencodeMock,
  tick,
  waitFor,
} from "./helpers/fakeHost.ts";

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
}

type AnyHooks = Record<string, ((...args: unknown[]) => Promise<unknown>) | undefined>;

function hooksOf(value: unknown): AnyHooks {
  return value as AnyHooks;
}

function hostile(): object {
  const boom = (): never => {
    throw new Error("hostile trap");
  };
  return new Proxy(
    {},
    { get: boom, has: boom, ownKeys: boom, getOwnPropertyDescriptor: boom, getPrototypeOf: boom },
  );
}

function fakeChecker(): PolicyChecker {
  return { checkTool: async () => ({ kind: "allow" }) };
}

// --- shape --------------------------------------------------------------------------------------

test("shape: exactly one export, default = { id: 'unbound', server, setup }, no tui", async () => {
  const mod = (await import("../src/index.ts")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(mod), ["default"]);
  const plugin = mod.default as Record<string, unknown>;
  assert.equal(plugin.id, "unbound");
  assert.equal(typeof plugin.server, "function");
  assert.equal(typeof plugin.setup, "function");
  assert.equal("tui" in plugin, false);
  assert.deepEqual(Object.keys(plugin).sort(), ["id", "server", "setup"]);
});

// --- no I/O in server() -------------------------------------------------------------------------

test("server() reads no env, no home and builds no checker, and settles before a macrotask", async () => {
  resetMock();
  const t = makeDeps(mock);
  let envReads = 0;
  let homeReads = 0;
  let checkers = 0;
  const realEnv = t.deps.env as NodeJS.ProcessEnv;
  const realHome = t.deps.homeDir as string;
  const env = new Proxy(realEnv, {
    get(target, key) {
      envReads += 1;
      return Reflect.get(target, key);
    },
  });
  const overrides = {
    ...t.deps,
    env,
    makeChecker: () => {
      checkers += 1;
      return fakeChecker();
    },
  };
  delete (overrides as { homeDir?: string }).homeDir;
  Object.defineProperty(overrides, "homeDir", {
    enumerable: true,
    get() {
      homeReads += 1;
      return realHome;
    },
  });
  try {
    const server = createServerPlugin(overrides);
    assert.equal(envReads, 0, "construction reads no env");
    assert.equal(homeReads, 0, "construction reads no home");
    const { input } = makeFakeInput({ directory: "/repo" });
    let macrotaskFired = false;
    const timer = setTimeout(() => {
      macrotaskFired = true;
    }, 0);
    const hooks = await server(input);
    assert.equal(macrotaskFired, false, "server() settled before a setTimeout(0)");
    clearTimeout(timer);
    assert.equal(typeof hooks, "object");
    assert.equal(envReads, 0);
    assert.equal(homeReads, 0);
    assert.equal(checkers, 0);
    assert.equal(mock.requests.length, 0);
  } finally {
    t.cleanup();
  }
});

// --- never rejects ------------------------------------------------------------------------------

test("server() resolves an object for null, undefined and a number", async () => {
  for (const value of [null, undefined, 42]) {
    const t = makeDeps(mock);
    try {
      const hooks = await createServerPlugin(t.deps)(value);
      assert.equal(typeof hooks, "object");
      assert.notEqual(hooks, null);
    } finally {
      t.cleanup();
    }
  }
});

test("a raising directory getter or a hostile proxy input → degraded set, one init_degraded", async () => {
  const raisingDirectory = {
    client: {},
    get directory(): string {
      throw new Error("directory getter raised");
    },
  };
  for (const value of [raisingDirectory, hostile()]) {
    resetMock();
    const t = makeDeps(mock);
    try {
      const hooks = hooksOf(await createServerPlugin(t.deps)(value));
      assert.equal(typeof hooks["tool.execute.before"], "function");
      assert.equal(typeof hooks.event, "function");
      assert.equal(hooks.config, undefined, "degraded set is not the full set");
      assert.equal(
        await hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "cat .env" } }),
        undefined,
      );
      assert.equal(await hooks.event?.({ event: { type: "session.created" } }), undefined);
      await hooks.event?.({ event: { type: "session.idle" } });
      assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_INIT_DEGRADED).length === 1));
      await tick();
      const sent = signalsOf(mock, SIGNAL_INIT_DEGRADED);
      assert.equal(sent.length, 1, "reported once");
      assert.equal((sent[0]?.body as { hook_source?: string }).hook_source, "opencode-hook");
      assert.equal(pretoolRequests(mock).length, 0, "degraded set never checks");
    } finally {
      t.cleanup();
    }
  }
});

// --- sentinel -----------------------------------------------------------------------------------

test("a second module copy on the same sentinel gets {} and reports duplicate_load once", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const first = createServerPlugin({ ...t.deps, moduleToken: createModuleToken() });
    const second = createServerPlugin({ ...t.deps, moduleToken: createModuleToken() });
    const a = hooksOf(await first(makeFakeInput({ directory: "/repo" }).input));
    assert.equal(typeof a.config, "function");
    const b = await second(makeFakeInput({ directory: "/repo" }).input);
    assert.deepEqual(Object.keys(b), []);
    await second(makeFakeInput({ directory: "/other" }).input);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length >= 1));
    await tick();
    assert.equal(signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length, 1);
  } finally {
    t.cleanup();
  }
});

test("the claimed sentinel slot is non-writable, non-configurable and non-enumerable (WR-04)", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const token = createModuleToken();
    await createServerPlugin({ ...t.deps, moduleToken: token })(makeFakeInput({ directory: "/repo" }).input);
    const key = t.deps.sentinelKey as symbol;
    const desc = Object.getOwnPropertyDescriptor(globalThis, key);
    assert.equal(desc?.value, token);
    assert.equal(desc?.writable, false);
    assert.equal(desc?.configurable, false);
    assert.equal(desc?.enumerable, false);
    assert.throws(() => {
      (globalThis as Record<symbol, unknown>)[key] = {};
    }, TypeError);
    assert.equal(Object.getOwnPropertyDescriptor(globalThis, key)?.value, token, "a later overwrite fails");
  } finally {
    t.cleanup();
  }
});

test("a value a foreign plugin planted in the slot never disables enforcement; sentinel_tampered (WR-04)", async () => {
  const key = (): symbol => Symbol("unbound.opencode.tamper");
  const planted: Array<[string, (k: symbol) => void]> = [
    ["plain object", (k) => void ((globalThis as Record<symbol, unknown>)[k] = { module: "unbound.opencode" })],
    ["true", (k) => void ((globalThis as Record<symbol, unknown>)[k] = true)],
    [
      "frozen non-configurable, wrong build",
      (k) =>
        Object.defineProperty(globalThis, k, {
          value: Object.freeze({ module: "unbound.opencode", build: "guess" }),
          writable: false,
          configurable: false,
        }),
    ],
    [
      "right build but writable",
      (k) => void ((globalThis as Record<symbol, unknown>)[k] = Object.freeze({ module: "unbound.opencode", build: "source" })),
    ],
    ["accessor", (k) => Object.defineProperty(globalThis, k, { get: () => ({}), configurable: true })],
    [
      "raising proxy",
      (k) =>
        Object.defineProperty(globalThis, k, {
          value: new Proxy({}, { getOwnPropertyDescriptor: () => { throw new Error("trap"); } }),
          writable: false,
          configurable: false,
        }),
    ],
  ];
  for (const [label, plant] of planted) {
    resetMock();
    mock.setMode("deny");
    const sentinelKey = key();
    plant(sentinelKey);
    const t = makeDeps(mock, { sentinelKey });
    try {
      const server = createServerPlugin(t.deps);
      const hooks = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
      assert.equal(typeof hooks["tool.execute.before"], "function", `${label}: full hook set`);
      assert.equal(typeof hooks.config, "function", `${label}: not the degraded set`);
      await assert.rejects(
        hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "cat .env" } }) ??
          Promise.resolve(),
        /Blocked by Unbound policy/,
        `${label}: still enforcing`,
      );
      // A second directory on the same copy still enforces too.
      const other = hooksOf(await server(makeFakeInput({ directory: "/other" }).input));
      assert.equal(typeof other.config, "function", `${label}: second directory enforces`);
      assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_SENTINEL_TAMPERED).length === 1), `${label}: reported`);
      await tick();
      assert.equal(signalsOf(mock, SIGNAL_SENTINEL_TAMPERED).length, 1, `${label}: once`);
      assert.equal(signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length, 0, `${label}: not a duplicate`);
    } finally {
      t.cleanup();
    }
  }
});

test("a configurable planted value is taken back, so a later copy of this build stands down (WR-04)", async () => {
  resetMock();
  const sentinelKey = Symbol("unbound.opencode.reclaim");
  (globalThis as Record<symbol, unknown>)[sentinelKey] = { evil: true };
  const t = makeDeps(mock, { sentinelKey });
  try {
    const mine = createModuleToken();
    await createServerPlugin({ ...t.deps, moduleToken: mine })(makeFakeInput({ directory: "/repo" }).input);
    assert.equal(Object.getOwnPropertyDescriptor(globalThis, sentinelKey)?.value, mine);
    const second = await createServerPlugin({ ...t.deps, moduleToken: createModuleToken() })(
      makeFakeInput({ directory: "/repo" }).input,
    );
    assert.deepEqual(Object.keys(second), []);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_SENTINEL_TAMPERED).length === 1));
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length === 1));
  } finally {
    t.cleanup();
  }
});

test("one module copy serving two directories is not a duplicate", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const server = createServerPlugin(t.deps);
    const a = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    const b = hooksOf(await server(makeFakeInput({ directory: "/other" }).input));
    assert.equal(typeof a.config, "function");
    assert.equal(typeof b.config, "function");
    await tick();
    assert.equal(signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length, 0);
  } finally {
    t.cleanup();
  }
});

// --- lazy init ----------------------------------------------------------------------------------

test("the first hook call resolves key/gateway/checker; later calls do not re-resolve", async () => {
  resetMock();
  const t = makeDeps(mock);
  let envReads = 0;
  let checkers = 0;
  const realEnv = t.deps.env as NodeJS.ProcessEnv;
  const env = new Proxy(realEnv, {
    get(target, key) {
      envReads += 1;
      return Reflect.get(target, key);
    },
  });
  try {
    const server = createServerPlugin({
      ...t.deps,
      env,
      makeChecker: () => {
        checkers += 1;
        return fakeChecker();
      },
    });
    const hooks = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    assert.equal(envReads, 0);
    await hooks.config?.({});
    assert.ok(envReads > 0, "the first hook resolves");
    assert.equal(checkers, 1);
    assert.equal(server.inspect.resolveCount(), 1);
    const readsAfterFirst = envReads;
    await hooks.config?.({});
    const other = hooksOf(await server(makeFakeInput({ directory: "/other" }).input));
    await other.config?.({});
    assert.equal(envReads, readsAfterFirst, "no re-resolution");
    assert.equal(checkers, 1, "one checker for the process copy");
    assert.equal(server.inspect.resolveCount(), 1);
  } finally {
    t.cleanup();
  }
});

test("with no key resolved nothing is constructed and no request is made", async () => {
  resetMock();
  const t = makeDeps(mock, { withKey: false });
  let checkers = 0;
  try {
    const server = createServerPlugin({
      ...t.deps,
      makeChecker: () => {
        checkers += 1;
        return fakeChecker();
      },
    });
    const hooks = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    await hooks.config?.({ mcp: { a: {} } });
    await tick();
    assert.equal(checkers, 0);
    assert.equal(server.inspect.hasChecker(), false);
    assert.equal(mock.requests.length, 0);
  } finally {
    t.cleanup();
  }
});

// --- config snapshot ----------------------------------------------------------------------------

test("config snapshots MCP server names per directory, read-only", async () => {
  const t = makeDeps(mock);
  try {
    const server = createServerPlugin(t.deps);
    const hooks = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    const cfg = { mcp: { "gh.com": { type: "remote" }, local_fs: { type: "local", command: ["x"] } }, model: "m" };
    const before = structuredClone(cfg);
    assert.equal(await hooks.config?.(cfg), undefined);
    assert.deepEqual(cfg, before, "config not mutated");
    assert.deepEqual(server.inspect.instance("/repo")?.mcpServerNames, ["gh.com", "local_fs"]);

    // A trailing slash is the same directory.
    assert.deepEqual(server.inspect.instance("/repo/")?.mcpServerNames, ["gh.com", "local_fs"]);

    const frozen = Object.freeze({ mcp: Object.freeze({ only: Object.freeze({}) }) });
    await hooks.config?.(frozen);
    assert.deepEqual(server.inspect.instance("/repo")?.mcpServerNames, ["only"]);

    for (const garbage of [null, [], { mcp: 5 }, { mcp: null }, { mcp: [1, 2] }, hostile()]) {
      assert.equal(await hooks.config?.(garbage), undefined);
      assert.deepEqual(server.inspect.instance("/repo")?.mcpServerNames, []);
    }

    // Directories are separate.
    const other = hooksOf(await server(makeFakeInput({ directory: "/other" }).input));
    await other.config?.({ mcp: { x: {} } });
    assert.deepEqual(server.inspect.instance("/other")?.mcpServerNames, ["x"]);
    assert.deepEqual(server.inspect.instance("/repo")?.mcpServerNames, []);
  } finally {
    t.cleanup();
  }
});

test("dispose releases the directory's state and resolves", async () => {
  const t = makeDeps(mock);
  try {
    const server = createServerPlugin(t.deps);
    const hooks = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    await hooks.config?.({ mcp: { a: {} } });
    assert.notEqual(server.inspect.instance("/repo"), undefined);
    assert.equal(await hooks.dispose?.(), undefined);
    assert.equal(server.inspect.instance("/repo"), undefined);
    assert.equal(await hooks.dispose?.(), undefined, "a second dispose is harmless");
  } finally {
    t.cleanup();
  }
});

test("a late dispose of a superseded instance does not release the live one's state (WR-05)", async () => {
  resetMock();
  const t = makeDeps(mock, { withKey: false });
  try {
    const server = createServerPlugin(t.deps);
    const oldFake = makeFakeInput({ directory: "/repo" });
    const oldHooks = hooksOf(await server(oldFake.input));
    const newFake = makeFakeInput({ directory: "/repo" });
    const newHooks = hooksOf(await server(newFake.input));
    const bash = (id: string): Promise<unknown> | undefined =>
      newHooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: id }, { args: { command: "ls" } });
    await bash("c1");
    await tick();
    assert.equal(newFake.toasts.filter((x) => x.message === NO_KEY_NOTICE).length, 1);

    assert.equal(await oldHooks.dispose?.(), undefined);
    assert.notEqual(server.inspect.instance("/repo"), undefined, "the live instance keeps its record");
    await bash("c2");
    await tick();
    assert.equal(newFake.toasts.filter((x) => x.message === NO_KEY_NOTICE).length, 1, "its no-key latch survived");

    assert.equal(await newHooks.dispose?.(), undefined);
    assert.equal(server.inspect.instance("/repo"), undefined, "the latest instance's dispose releases");

    // After a release and a fresh server(), a repeated dispose of the old set is still a no-op.
    const fresh = hooksOf(await server(makeFakeInput({ directory: "/repo" }).input));
    assert.equal(await newHooks.dispose?.(), undefined);
    assert.notEqual(server.inspect.instance("/repo"), undefined, "a stale record never releases its successor");
    assert.equal(await fresh.dispose?.(), undefined);
    assert.equal(server.inspect.instance("/repo"), undefined);
  } finally {
    t.cleanup();
  }
});

// --- v2 setup -----------------------------------------------------------------------------------

/** The ctx keys the 1.18 CLI's embedded core host passes to `setup` (13-SPIKES.md V1-2b). */
function v118Ctx(): Record<string, unknown> {
  const ctx: Record<string, unknown> = {};
  for (const key of ["options", "agent", "aisdk", "catalog", "command", "integration", "plugin", "reference", "skill"]) {
    ctx[key] = {};
  }
  return ctx;
}

test("setup is inert on a 1.18 ctx and on garbage: resolves undefined, reports nothing", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setup = createSetupV2({ ...t.deps, sentinelKey: Symbol("v2-test") });
    for (const ctx of [null, undefined, {}, 42, v118Ctx(), hostile()]) {
      const pending = setup(ctx);
      assert.ok(pending instanceof Promise);
      assert.equal(await pending, undefined);
    }
    await tick(100);
    assert.equal(signalsOf(mock, SIGNAL_API_FAMILY_INACTIVE).length, 0);
    assert.equal(mock.requests.length, 0);
  } finally {
    t.cleanup();
  }
});

test("setup on a v2 ctx reports api_family_inactive once per process, never enforcing", async () => {
  for (const ctx of [{ ...v118Ctx(), tool: {}, permission: {} }, { session: {} }]) {
    resetMock();
    const t = makeDeps(mock);
    const sentinelKey = Symbol("v2-test");
    try {
      const setup = createSetupV2({ ...t.deps, sentinelKey });
      assert.equal(await setup(ctx), undefined);
      assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_API_FAMILY_INACTIVE).length === 1));
      const body = signalsOf(mock, SIGNAL_API_FAMILY_INACTIVE)[0]?.body as {
        hook_source?: string;
        errors?: Array<{ message?: string }>;
      };
      assert.equal(body.hook_source, "opencode-hook");
      assert.match(body.errors?.[0]?.message ?? "", /v2_setup_inactive/);
      assert.match(body.errors?.[0]?.message ?? "", /tool=setup/);
      // A second call, and a second copy on the same slot, report nothing more.
      assert.equal(await setup(ctx), undefined);
      assert.equal(await createSetupV2({ ...t.deps, sentinelKey })(ctx), undefined);
      await tick(100);
      assert.equal(signalsOf(mock, SIGNAL_API_FAMILY_INACTIVE).length, 1);
      assert.equal(pretoolRequests(mock).length, 0);
    } finally {
      delete (globalThis as Record<symbol, unknown>)[sentinelKey];
      t.cleanup();
    }
  }
});

test("setup does not claim or disturb the server sentinel", async () => {
  resetMock();
  const t = makeDeps(mock);
  try {
    const setupKey = Symbol("v2-test");
    const setup = createSetupV2({ ...t.deps, sentinelKey: setupKey });
    await setup({ tool: {}, permission: {} });
    const hooks = hooksOf(await createServerPlugin(t.deps)(makeFakeInput({ directory: "/repo" }).input));
    assert.equal(typeof hooks.config, "function");
    await tick(50);
    assert.equal(signalsOf(mock, SIGNAL_DUPLICATE_LOAD).length, 0);
    delete (globalThis as Record<symbol, unknown>)[setupKey];
  } finally {
    t.cleanup();
  }
});
