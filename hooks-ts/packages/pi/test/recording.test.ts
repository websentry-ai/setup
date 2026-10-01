// What the turn record does while the extension has no authority — no key, or a latched key.
//
// The leak this closes: `tool_result` appended to the process-wide record unconditionally, on the
// reasoning that "a hash is cheaper than the branch to skip it" and that `agent_end` decides whether
// anything is sent. Both halves were true and the conclusion was still wrong, because in the inactive
// states `agent_end` returns *before* `take()`:
//
//   * **No key.** `input` and `tool_call` return early, so no turn is ever started — which means
//     `take()`'s empty-turn guard would not clear `results` even if it ran. Every tool result of every
//     turn accumulated, with a sha256 computed over as much as 4 MB of output each, for the lifetime
//     of the process.
//   * **A latched key.** `agent_end` does take the record, so the first turn drains — and then results
//     pile up again behind a `checkTool` that is answering from the latch without any HTTP.
//
// So the rule is now the honest one: if nothing will ever post this record, nothing records into it.
// `agent_end` still takes in both states, so anything already pending is released rather than pinned.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { keyState } from "../../core/src/keyState.ts";
import { turnStore } from "../../core/src/turn.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import {
  createFakeAgentEndEvent,
  createFakeCtx,
  createFakeInputEvent,
  createFakeToolCallEvent,
  createFakeToolResultEvent,
} from "./helpers/fakeCtx.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TURNLOG_PATH = PI_PROFILE.turnLogPath;

const SESSION = "sess-recording-1";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const turnLogs = (api: MockApi) => api.requests.filter((r) => r.path === TURNLOG_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/** Closed, so `session_start` sends neither a heartbeat nor a presence row. */
const closedGate: Deps["heartbeatGate"] = { shouldSend: () => false, markSent: () => {} };

interface Fixture {
  handlers: Map<string, AnyHandler>;
  cleanup(): void;
}

async function fixture(env: Record<string, string>): Promise<Fixture> {
  const homeDir = mkdtempSync(join(tmpdir(), "pi-recording-"));
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension({
    env,
    homeDir,
    entrypoint: "pi/0.87.1",
    heartbeatGate: closedGate,
  })(pi as unknown as ExtensionAPI);
  return { handlers, cleanup: () => rmSync(homeDir, { recursive: true, force: true }) };
}

function handlerOf(f: Fixture, name: string): AnyHandler {
  const handler = f.handlers.get(name);
  assert.ok(handler !== undefined, `${name} must be registered`);
  return handler;
}

// Declaration order matters in this file for the same reason it does in `compose.test.ts`: `keyState`
// is a module-scope singleton and the latch is permanent, so the keyless cases run FIRST and the
// latch case runs last.

test("a keyless session records nothing, however many results arrive", async () => {
  const f = await fixture({});
  try {
    const ctx = createFakeCtx({ sessionId: SESSION });
    const toolResult = handlerOf(f, "tool_result");

    // The prompt and the call are already inert without a key; the result was not.
    assert.equal(await handlerOf(f, "input")(createFakeInputEvent("summarise this"), ctx), undefined);
    assert.equal(await handlerOf(f, "tool_call")(createFakeToolCallEvent("bash", { command: "ls" }), ctx), undefined);

    for (let i = 0; i < 100; i += 1) {
      const event = createFakeToolResultEvent("bash", {
        content: [{ type: "text", text: `output ${i}` }],
      });
      assert.equal(await toolResult(event, ctx), undefined, "and it still never rewrites a result");
    }

    assert.deepEqual(
      turnStore.snapshot(),
      { tool_calls: [], results: [] },
      "100 results, nothing retained, no session stamped",
    );
  } finally {
    f.cleanup();
  }
});

test("a keyless agent_end releases a pending record instead of pinning it", async () => {
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture({});
  try {
    const ctx = createFakeCtx({ sessionId: SESSION });
    // However it got there — a key removed mid-session, a `/reload` — a pending record must not
    // outlive the turn just because this session cannot post it.
    turnStore.recordPrompt("left over", SESSION);
    turnStore.recordResult({ tool_name: "bash", tool_use_id: "call_1", is_error: false, content_bytes: 2 });

    handlerOf(f, "agent_end")(createFakeAgentEndEvent([]), ctx);
    await sleep(60);

    assert.deepEqual(turnStore.snapshot(), { tool_calls: [], results: [] }, "taken and dropped");
    assert.deepEqual(turnLogs(api), [], "and nothing was sent without a key");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("a latched key stops recording too, and does not accumulate behind the latch", async () => {
  const api = await startMockApi({ mode: "401" });
  const f = await fixture({ UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url });
  try {
    const ctx = createFakeCtx({ sessionId: SESSION });
    const toolCall = handlerOf(f, "tool_call");

    // Two consecutive 401s with nothing remembered: the session latches and goes inactive.
    await toolCall(createFakeToolCallEvent("bash", { command: "ls" }), ctx);
    await toolCall(createFakeToolCallEvent("bash", { command: "ls" }), ctx);
    assert.equal(keyState.isInactive(), true, "the latch is what this case is about");

    // Whatever the latching turn left behind is released here, exactly as before.
    handlerOf(f, "agent_end")(createFakeAgentEndEvent([]), ctx);
    assert.deepEqual(turnStore.snapshot(), { tool_calls: [], results: [] });

    // From here the record must stay empty: nothing will ever post it.
    await toolCall(createFakeToolCallEvent("bash", { command: "ls" }), ctx);
    await handlerOf(f, "input")(createFakeInputEvent("still typing"), ctx);
    for (let i = 0; i < 50; i += 1) {
      await handlerOf(f, "tool_result")(createFakeToolResultEvent("bash"), ctx);
    }

    assert.deepEqual(
      turnStore.snapshot(),
      { tool_calls: [], results: [] },
      "an inactive session records nothing at all",
    );
    await sleep(60);
    assert.deepEqual(turnLogs(api), [], "and posts nothing");
  } finally {
    f.cleanup();
    await api.close();
  }
});
