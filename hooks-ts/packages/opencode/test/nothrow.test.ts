// HOOK-09 nothrow matrix: every registered hook × every fault. The assertion is that the returned
// promise RESOLVES. For the decision hooks (`tool.execute.before`, `chat.message`, `shell.env`) that
// proves "no block", because a block is a rejection. The last test is the sanity case: under a real
// deny a bash call DOES reject, so the matrix is not vacuous.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENY_PREFIX } from "../../core/src/constants.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { createServerPlugin } from "../src/plugin.ts";
import type { Deps } from "../src/plugin.ts";
import { makeDeps, makeFakeInput, startOpencodeMock, tick } from "./helpers/fakeHost.ts";
import type { ToastMode } from "./helpers/fakeHost.ts";
import { hostile, outcome, OPENROUTER_MODEL } from "./helpers/harness.ts";
import type { Hooks } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const S = "ses_root";
const EXPECTED_HOOKS = [
  "config",
  "dispose",
  "event",
  "tool.execute.before",
  "tool.execute.after",
  "chat.message",
  "shell.env",
] as const;

/** A session-id getter that raises. */
function raisingSessionInput(extra: Record<string, unknown> = {}): object {
  return Object.defineProperty({ ...extra }, "sessionID", {
    enumerable: true,
    get() {
      throw new Error("sessionID getter");
    },
  });
}

/** Realistic calls of every hook, so faults deeper in the decision path are reached. */
function realisticCalls(): Array<[string, unknown[]]> {
  return [
    ["config", [{ mcp: { my: {} } }]],
    ["event", [{ event: { type: "session.created", properties: { sessionID: S, info: { id: S, directory: "/repo", version: "1.18.34" } } } }]],
    ["chat.message", [{ sessionID: S, model: OPENROUTER_MODEL }, { message: {}, parts: [{ type: "text", text: "read .env" }] }]],
    ["tool.execute.before", [{ tool: "bash", sessionID: S, callID: "c1" }, { args: { command: "cat .env" } }]],
    ["tool.execute.before", [{ tool: "read", sessionID: S, callID: "c2" }, { args: { filePath: "/repo/.env" } }]],
    ["tool.execute.before", [{ tool: "apply_patch", sessionID: S, callID: "c3" }, { args: { patchText: "*** Begin Patch\n*** Update File: a.ts\n*** End Patch" } }]],
    ["tool.execute.after", [{ tool: "bash", sessionID: S, callID: "c1", args: { command: "rm -rf ~" } }, { title: "", output: "x", metadata: {} }]],
    [
      "event",
      [{ event: { type: "message.part.updated", properties: { sessionID: S, part: { id: "p", sessionID: S, messageID: "m", type: "tool", tool: "bash", callID: "u1", state: { status: "running", input: { command: "cat .env" } } } } } }],
    ],
    ["shell.env", [{ cwd: "/repo", sessionID: S, callID: "u1" }, { env: {} }]],
    ["shell.env", [{ cwd: "/repo", sessionID: S, callID: "unknown" }, { env: {} }]],
    ["event", [{ event: { type: "session.idle", properties: { sessionID: S } } }]],
    ["event", [{ event: { type: "session.deleted", properties: { sessionID: S, info: { id: S } } } }]],
    ["dispose", []],
  ];
}

/** Degenerate inputs for every hook (faults 4, 5, 6). */
function degenerateCalls(name: string): unknown[][] {
  const values: unknown[] = [null, undefined, 42, "x", hostile()];
  const calls: unknown[][] = [];
  for (const v of values) {
    calls.push([v, v]);
    calls.push([{ tool: "bash", sessionID: S, callID: "d1" }, v]);
    calls.push([v, { args: { command: "ls" }, parts: [{ type: "text", text: "hi" }], env: {} }]);
  }
  // output.args / output.parts / output.env of the wrong type.
  for (const v of [null, undefined, 7, hostile()]) {
    calls.push([{ tool: "bash", sessionID: S, callID: "d2" }, { args: v }]);
    calls.push([{ sessionID: S }, { message: {}, parts: v }]);
    calls.push([{ cwd: "/repo", sessionID: S, callID: "d3" }, { env: v }]);
  }
  // A raising sessionID getter.
  calls.push([raisingSessionInput({ tool: "bash", callID: "d4" }), { args: { command: "ls" } }]);
  calls.push([raisingSessionInput(), { message: {}, parts: [{ type: "text", text: "hi" }] }]);
  if (name === "event") {
    for (const v of [null, undefined, 3, hostile()]) {
      calls.push([{ event: v }]);
      for (const type of ["session.created", "session.idle", "session.deleted", "message.updated", "message.part.updated", "x"]) {
        calls.push([{ event: { type, properties: v } }]);
      }
    }
  }
  return calls;
}

interface Built {
  hooks: Hooks;
  cleanup(): void;
}

async function build(
  mode: MockMode,
  deps: Partial<Deps> & { withKey?: boolean } = {},
  host: { toast?: ToastMode; sessionGetRaises?: boolean } = {},
  patchDeps?: (deps: Partial<Deps>) => void,
): Promise<Built> {
  mock.requests.length = 0;
  mock.setMode(mode);
  const t = makeDeps(mock, { timeouts: { pretoolMs: 200, errorsMs: 200, turnLogMs: 200 }, deadlineMs: 400, ...deps });
  patchDeps?.(t.deps);
  const server = createServerPlugin(t.deps);
  const fake = makeFakeInput({ directory: "/repo", ...(host.toast === undefined ? {} : { toast: host.toast }) });
  if (host.sessionGetRaises === true) {
    fake.input.client.session.get = () => {
      throw new Error("session.get raised");
    };
  }
  const hooks = (await server(fake.input)) as Hooks;
  return { hooks, cleanup: t.cleanup };
}

async function assertAllResolve(b: Built, label: string): Promise<void> {
  for (const [name, args] of realisticCalls()) {
    const fn = b.hooks[name];
    assert.equal(typeof fn, "function", `${label}: ${name} registered`);
    assert.equal(await outcome((fn as (...a: unknown[]) => Promise<unknown>)(...args)), undefined, `${label}: ${name} resolves`);
  }
  for (const name of EXPECTED_HOOKS) {
    const fn = b.hooks[name] as (...a: unknown[]) => Promise<unknown>;
    for (const args of degenerateCalls(name)) {
      let r: string | undefined;
      try {
        r = await outcome(fn(...args));
      } catch (err) {
        assert.fail(`${label}: ${name} raised synchronously: ${String(err)}`);
      }
      assert.equal(r, undefined, `${label}: ${name} resolves on degenerate input`);
    }
  }
}

function checker(checkTool: PolicyChecker["checkTool"]): Partial<Deps> {
  return { makeChecker: () => ({ checkTool }) };
}

test("every expected hook is registered", async () => {
  const b = await build("allow");
  try {
    assert.deepEqual(Object.keys(b.hooks).sort(), [...EXPECTED_HOOKS].sort());
  } finally {
    b.cleanup();
  }
});

test("fault 1: a checker that raises synchronously never blocks", async () => {
  const b = await build("allow", checker(() => {
    throw new Error("sync raise");
  }));
  try {
    await assertAllResolve(b, "sync raise");
  } finally {
    b.cleanup();
  }
});

test("fault 2: a checker that rejects never blocks", async () => {
  const b = await build("allow", checker(() => Promise.reject(new Error("rejected"))));
  try {
    await assertAllResolve(b, "reject");
  } finally {
    b.cleanup();
  }
});

for (const garbage of [null, "deny", { kind: 5 }] as const) {
  test(`fault 3: a garbage verdict ${JSON.stringify(garbage)} never blocks`, async () => {
    const b = await build("allow", checker(() => Promise.resolve(garbage as never)));
    try {
      await assertAllResolve(b, `garbage ${JSON.stringify(garbage)}`);
    } finally {
      b.cleanup();
    }
  });
}

test("faults 4-6: null / undefined / number / hostile inputs and outputs, raising sessionID getters (mock allow)", async () => {
  const b = await build("allow");
  try {
    await assertAllResolve(b, "degenerate");
  } finally {
    b.cleanup();
  }
});

for (const toast of ["raise", "hang"] as const) {
  test(`fault 7: a client whose toast ${toast}s and whose session.get raises never blocks (no key: notices fire)`, async () => {
    const b = await build("allow", { withKey: false }, { toast, sessionGetRaises: true });
    try {
      await assertAllResolve(b, `toast ${toast}`);
    } finally {
      b.cleanup();
    }
  });
}

test("fault 7: a raising toast with a key and a 500 gateway never blocks", async () => {
  const b = await build("500", {}, { toast: "raise", sessionGetRaises: true });
  try {
    await assertAllResolve(b, "toast raise 500");
  } finally {
    b.cleanup();
  }
});

test("fault 8: init error (env Proxy that raises, raising homeDir getter) resolves a working, allowing hook set", async () => {
  const raisingEnv = new Proxy({}, {
    get() {
      throw new Error("env get");
    },
    has() {
      throw new Error("env has");
    },
    ownKeys() {
      throw new Error("env keys");
    },
  }) as NodeJS.ProcessEnv;
  // Patched after the test helper built its deps (the helper itself would read the getter).
  const b = await build("deny", {}, {}, (deps) => {
    deps.env = raisingEnv;
    Object.defineProperty(deps, "homeDir", {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error("homeDir getter");
      },
    });
  });
  try {
    await assertAllResolve(b, "init error");
    await tick();
    assert.equal(mock.requests.filter((r) => r.path === "/v1/hooks/pretool").length, 0);
  } finally {
    b.cleanup();
  }
});

test("fault 9: mock deny for a non-evaluable custom tool still resolves", async () => {
  const b = await build("deny");
  try {
    const fn = b.hooks["tool.execute.before"] as (...a: unknown[]) => Promise<unknown>;
    assert.equal(await outcome(fn({ tool: "my_custom_tool", sessionID: S, callID: "x1" }, { args: { a: 1 } })), undefined);
  } finally {
    b.cleanup();
  }
});

test("sanity: under mock deny a bash call DOES reject (the matrix is not vacuous)", async () => {
  const b = await build("deny");
  try {
    const fn = b.hooks["tool.execute.before"] as (...a: unknown[]) => Promise<unknown>;
    const message = await outcome(fn({ tool: "bash", sessionID: S, callID: "s1" }, { args: { command: "cat .env" } }));
    assert.ok(message?.startsWith(DENY_PREFIX), `rejected with the deny text: ${message}`);
  } finally {
    b.cleanup();
  }
});
