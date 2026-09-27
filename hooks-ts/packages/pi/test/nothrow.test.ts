// RES-01 at the pi boundary — the guarantee that the registered handlers cannot throw.
//
// `ExtensionRunner.emitToolCall` has no try/catch (§F1): an exception from our handler is turned by
// agent-core into a **block** whose message — our internal exception text — is handed to the model
// (§B5). The try/catch inside each handler is therefore the entire fail-open mechanism, and it has
// to cover the payload build and the key lookup too, both of which touch the filesystem.
//
// So every fault below is injected at a different depth: the policy checker raising synchronously,
// the checker rejecting, `ctx` itself raising, and `ctx.ui.notify` raising.

import assert from "node:assert/strict";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import extension, { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx } from "./helpers/fakeCtx.ts";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

interface Stub {
  api: ExtensionAPI;
  registered: string[];
  handlers: Map<string, AnyHandler>;
}

function stubApi(): Stub {
  const registered: string[] = [];
  const handlers = new Map<string, AnyHandler>();
  const api = {
    on(event: string, handler: AnyHandler) {
      registered.push(event);
      handlers.set(event, handler);
      return () => {};
    },
  };
  return { api: api as unknown as ExtensionAPI, registered, handlers };
}

/** Build the extension with injected deps and return its registered handlers. */
async function build(overrides: Partial<Deps>): Promise<Stub> {
  const stub = stubApi();
  await createExtension(overrides)(stub.api);
  return stub;
}

function keyedEnv(gatewayUrl: string): NodeJS.ProcessEnv {
  return { UNBOUND_PI_API_KEY: "unb_test_key_1234567890", UNBOUND_GATEWAY_URL: gatewayUrl };
}

/** A checker that is never reached by a well-behaved path. */
function checkerThatRaises(): PolicyChecker {
  return {
    checkTool() {
      throw new Error("core exploded synchronously");
    },
  };
}

async function callToolCall(stub: Stub, ctx: FakeCtx): Promise<unknown> {
  const handler = stub.handlers.get("tool_call");
  assert.ok(handler !== undefined, "tool_call must be registered");
  return await handler(createFakeToolCallEvent("bash", { command: "cat /etc/shadow" }), ctx);
}

test("RES-01 a policy checker that raises synchronously still allows the call", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: keyedEnv("http://127.0.0.1:1"),
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
      makeChecker: () => checkerThatRaises(),
    });

    let result: unknown = "unset";
    await assert.doesNotReject(async () => {
      result = await callToolCall(stub, createFakeCtx());
    }, "a raising core must not become a thrown handler");
    assert.equal(result, undefined);
  } finally {
    home.cleanup();
  }
});

test("RES-01 a policy checker that rejects still allows the call", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: keyedEnv("http://127.0.0.1:1"),
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
      makeChecker: () => ({
        checkTool: async () => {
          await Promise.resolve();
          throw new Error("core rejected");
        },
      }),
    });

    let result: unknown = "unset";
    await assert.doesNotReject(async () => {
      result = await callToolCall(stub, createFakeCtx());
    });
    assert.equal(result, undefined);
  } finally {
    home.cleanup();
  }
});

test("RES-01 a ctx whose getSessionId raises still allows the call", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: keyedEnv("http://127.0.0.1:1"),
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
      makeChecker: () => ({ checkTool: async () => ({ kind: "allow" }) }),
    });

    const ctx = createFakeCtx();
    ctx.sessionManager = {
      getSessionId() {
        throw new Error("no session");
      },
    };

    let result: unknown = "unset";
    await assert.doesNotReject(async () => {
      result = await callToolCall(stub, ctx);
    }, "the payload build must sit inside the try");
    assert.equal(result, undefined);
  } finally {
    home.cleanup();
  }
});

test("RES-01 undefined model and signal are normal: no throw, and model falls back to auto", async () => {
  const api = await startMockApi({ mode: "allow" });
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: keyedEnv(api.url),
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
    });

    const ctx = createFakeCtx({ modelId: undefined, signal: undefined });
    let result: unknown = "unset";
    await assert.doesNotReject(async () => {
      result = await callToolCall(stub, ctx);
    });

    assert.equal(result, undefined);
    const body = api.requests[0]?.body as Record<string, unknown>;
    assert.equal(body.model, "auto", "never the string 'undefined' on a required field");
  } finally {
    home.cleanup();
    await api.close();
  }
});

test("RES-01 session_start survives a ctx.ui.notify that raises", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: { UNBOUND_GATEWAY_URL: "http://127.0.0.1:1" },
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
    });

    const ctx = createFakeCtx();
    ctx.ui.notify = () => {
      throw new Error("notify exploded");
    };

    const handler = stub.handlers.get("session_start");
    assert.ok(handler !== undefined);
    await assert.doesNotReject(async () => {
      await handler({ type: "session_start", reason: "startup" }, ctx);
    }, "a cosmetic notice must never break startup");
  } finally {
    home.cleanup();
  }
});

test("RES-01 the default export is a factory registering exactly tool_call and session_start", async () => {
  assert.equal(typeof extension, "function", "pi loads a default-export factory (§A1)");

  const stub = stubApi();
  await assert.doesNotReject(async () => {
    await extension(stub.api);
  });

  assert.equal(stub.registered.length, 2, `registered ${stub.registered.join(", ")}`);
  assert.deepStrictEqual([...stub.registered].sort(), ["session_start", "tool_call"]);
});
