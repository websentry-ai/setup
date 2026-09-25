// RES-06 — with no API key the extension is inert.
//
// This is a deliberate product rule, not a degraded mode: a developer who has not run `unbound
// login` must not have their tools blocked by an extension that cannot evaluate anything, and the
// extension must not fabricate a verdict. So: zero HTTP, zero blocks, and exactly one notice per
// session — mirrored to stderr when there is no UI, because `noOpUIContext.notify` silently drops it
// under `pi -p` / `--mode json` (§A6), and stdout is the machine-readable channel (§F9).

import assert from "node:assert/strict";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx } from "./helpers/fakeCtx.ts";

const NO_KEY_NOTICE = "Unbound: no API key found — extension inactive";
const SESSION_START = { type: "session_start", reason: "startup" };

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

interface Stub {
  api: ExtensionAPI;
  handlers: Map<string, AnyHandler>;
}

function stubApi(): Stub {
  const handlers = new Map<string, AnyHandler>();
  const api = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  return { api: api as unknown as ExtensionAPI, handlers };
}

async function build(overrides: Partial<Deps>): Promise<Stub> {
  const stub = stubApi();
  await createExtension(overrides)(stub.api);
  return stub;
}

async function toolCall(stub: Stub, ctx: FakeCtx): Promise<unknown> {
  const handler = stub.handlers.get("tool_call");
  assert.ok(handler !== undefined);
  return await handler(createFakeToolCallEvent("bash", { command: "cat /etc/shadow" }), ctx);
}

async function sessionStart(stub: Stub, ctx: FakeCtx): Promise<void> {
  const handler = stub.handlers.get("session_start");
  assert.ok(handler !== undefined);
  await handler(SESSION_START, ctx);
}

test("RES-06 no key: the tool_call handler is a no-op with zero HTTP and zero blocks", async () => {
  // A deny-scripted API proves the point: if a request were made, the result would be a block.
  const api = await startMockApi({ mode: "deny" });
  const home = createFakeHome({ gateway_url: api.url });
  try {
    const stub = await build({ env: {}, homeDir: home.homeDir, entrypoint: "pi/0.87.1" });

    const result = await toolCall(stub, createFakeCtx());

    assert.equal(result, undefined, "never a block without a key");
    assert.equal(api.requests.length, 0, "not one request");
  } finally {
    home.cleanup();
    await api.close();
  }
});

test("RES-06 no key: session_start notifies exactly once, at info level", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({ env: {}, homeDir: home.homeDir, entrypoint: "pi/0.87.1" });
    const ctx = createFakeCtx();

    await sessionStart(stub, ctx);

    assert.equal(ctx.notifyCalls.length, 1);
    assert.deepStrictEqual(ctx.notifyCalls[0], { message: NO_KEY_NOTICE, type: "info" });
  } finally {
    home.cleanup();
  }
});

test("RES-06 no key: a second session_start does not notify again", async () => {
  const home = createFakeHome({});
  try {
    const stub = await build({ env: {}, homeDir: home.homeDir, entrypoint: "pi/0.87.1" });
    const ctx = createFakeCtx();

    await sessionStart(stub, ctx);
    await sessionStart(stub, ctx);

    assert.equal(ctx.notifyCalls.length, 1, "one notice per extension instance");
  } finally {
    home.cleanup();
  }
});

test("RES-06 no key, headless: the notice goes to stderr and never to stdout", async () => {
  const home = createFakeHome({});
  const originalErr = process.stderr.write.bind(process.stderr);
  const originalOut = process.stdout.write.bind(process.stdout);
  const stderrChunks: string[] = [];
  const stdoutChunks: string[] = [];
  try {
    const stub = await build({ env: {}, homeDir: home.homeDir, entrypoint: "pi/0.87.1" });
    const ctx = createFakeCtx({ hasUI: false, mode: "json" });

    process.stderr.write = ((chunk: unknown): boolean => {
      stderrChunks.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    process.stdout.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
      stdoutChunks.push(String(chunk));
      // Forwarded: node:test writes its own TAP output through here.
      return (originalOut as (...args: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stdout.write;

    await sessionStart(stub, ctx);

    process.stderr.write = originalErr;
    process.stdout.write = originalOut;

    assert.equal(ctx.notifyCalls.length, 0, "there is no UI to notify");
    assert.equal(
      stderrChunks.some((c) => c.includes(NO_KEY_NOTICE)),
      true,
      `stderr chunks: ${JSON.stringify(stderrChunks)}`,
    );
    assert.equal(
      stdoutChunks.some((c) => c.includes(NO_KEY_NOTICE)),
      false,
      "stdout is pi's JSON/print channel (§F9)",
    );
  } finally {
    process.stderr.write = originalErr;
    process.stdout.write = originalOut;
    home.cleanup();
  }
});

test("RES-06 with a key: session_start is silent and tool_call issues exactly one request", async () => {
  const api = await startMockApi({ mode: "allow" });
  const home = createFakeHome({});
  try {
    const stub = await build({
      env: { UNBOUND_PI_API_KEY: "unb_test_key_1234567890", UNBOUND_GATEWAY_URL: api.url },
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
    });
    const ctx = createFakeCtx();

    await sessionStart(stub, ctx);
    assert.equal(ctx.notifyCalls.length, 0, "a configured extension says nothing at startup");

    const result = await toolCall(stub, ctx);

    assert.equal(result, undefined, "the scripted verdict is allow");
    assert.equal(api.requests.length, 1, "exactly one policy call");
    assert.equal(api.requests[0]?.path, "/v1/hooks/pretool");
    assert.equal(
      api.requests[0]?.headers.authorization,
      "Bearer unb_test_key_1234567890",
      "the resolved key authenticates the call",
    );
  } finally {
    home.cleanup();
    await api.close();
  }
});

test("RES-06 the key resolves from ~/.unbound/config.json when no env var is set", async () => {
  const api = await startMockApi({ mode: "allow" });
  const home = createFakeHome({ api_key: "unb_from_config_file_000", gateway_url: api.url });
  try {
    const stub = await build({ env: {}, homeDir: home.homeDir, entrypoint: "pi/0.87.1" });
    const ctx = createFakeCtx();

    await sessionStart(stub, ctx);
    const result = await toolCall(stub, ctx);

    assert.equal(ctx.notifyCalls.length, 0);
    assert.equal(result, undefined);
    assert.equal(api.requests.length, 1);
    assert.equal(api.requests[0]?.headers.authorization, "Bearer unb_from_config_file_000");
  } finally {
    home.cleanup();
    await api.close();
  }
});
