// The turn store across a session change (`/new`, `/resume`, `/fork`, `/clone`).
//
// The turn record is process-wide by necessity: it has to survive from `input` through every
// `tool_call` and `tool_result` to `agent_end`, which are four separate handler invocations. But pi's
// session id is NOT process-wide — `session_start` fires again on every session transition with a new
// one — and two things previously conspired to let one record outlive the session it described:
//
//   1. `startTurn` stamped `session_id` once and refused to replace it, by design ("whichever event
//      arrives first stamps it"). Correct within a session, wrong across one.
//   2. `user_bash` records a tool call but pi fires no `agent_end` for a bare `!cmd`, so that record
//      can still be pending when the developer types `/new`.
//
// Result: the next turn was posted to `/v1/hooks/pi` under the PREVIOUS `conversation_id`, carrying
// the old session's prompt, the old `!cmd` and the old start time — a turn log that describes a
// conversation that never happened. `conversation_id` becomes `thread_id` server-side (§B2), so this
// is not a cosmetic mislabel: it stitches two conversations into one thread.
//
// Two mechanisms close it, and both are asserted here because either alone leaves a hole:
//
//   * `session_start` **drops** a pending record that does not belong to the session now starting.
//     Dropped rather than posted, deliberately: `agent_end` never fired for it, so nothing says the
//     turn finished, and `session_start` is awaited by pi — a POST on that path would put the network
//     between the developer and their prompt. One lost partial row is the cheaper failure. It is
//     keyed on the id rather than unconditional so that a `/reload` re-firing with the same session,
//     or a ctx whose id cannot be read at all, cannot discard a turn that is still mid-flight.
//   * `startTurn` **adopts** a session id that differs from the stored one, dropping the old record.
//     That is the backstop for any path where `session_start` did not reach us first.
//
// The heartbeat gate is stubbed closed in every case here, which also pins the ordering: the drop
// happens before the gate check and before the no-key return, so the only `/v1/hooks/pi` request any
// case can produce is a real turn log.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { turnStore } from "../../core/src/turn.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import {
  createFakeAgentEndEvent,
  createFakeAssistantMessage,
  createFakeCtx,
  createFakeInputEvent,
  createFakeSessionStartEvent,
  createFakeToolCallEvent,
  createFakeUserBashEvent,
} from "./helpers/fakeCtx.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TURNLOG_PATH = PI_PROFILE.turnLogPath;

const SESSION_A = "session-old-aaa";
const SESSION_B = "session-new-bbb";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const turnLogs = (api: MockApi) => api.requests.filter((r) => r.path === TURNLOG_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/** Closed for the life of the case: no heartbeat, no presence row, so the only POST is a turn log. */
const closedGate: Deps["heartbeatGate"] = {
  shouldSend: () => false,
  markSent: () => {},
};

interface Fixture {
  handlers: Map<string, AnyHandler>;
  cleanup(): void;
}

async function fixture(api: MockApi): Promise<Fixture> {
  // A temp HOME is not optional: the composition root resolves a real cache path from it.
  const homeDir = mkdtempSync(join(tmpdir(), "pi-session-"));
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  await createExtension({
    env: { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url },
    homeDir,
    entrypoint: "pi/0.87.1",
    heartbeatGate: closedGate,
  })(pi as unknown as ExtensionAPI);
  return {
    handlers,
    cleanup: () => rmSync(homeDir, { recursive: true, force: true }),
  };
}

function handlerOf(f: Fixture, name: string): AnyHandler {
  const handler = f.handlers.get(name);
  assert.ok(handler !== undefined, `${name} must be registered`);
  return handler;
}

/** The turn-log bodies, in order, with only the fields these cases assert on. */
function postedTurns(api: MockApi): { conversation_id: string; prompt: string; tools: string[] }[] {
  return turnLogs(api).map((request) => {
    const body = request.body as {
      conversation_id?: unknown;
      messages?: { content?: unknown; tool_use?: { tool_name?: unknown }[] }[];
    };
    return {
      conversation_id: typeof body.conversation_id === "string" ? body.conversation_id : "",
      prompt: typeof body.messages?.[0]?.content === "string" ? body.messages[0].content : "",
      tools: (body.messages?.[1]?.tool_use ?? []).map((use) =>
        typeof use?.tool_name === "string" ? use.tool_name : "",
      ),
    };
  });
}

test("a turn started in one session is never posted under the next one", async () => {
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture(api);
  try {
    const ctxA = createFakeCtx({ sessionId: SESSION_A });
    const ctxB = createFakeCtx({ sessionId: SESSION_B });

    // Session A: a prompt is checked and recorded, and then the developer types `/new` without the
    // run ever ending. Nothing has posted this record.
    await handlerOf(f, "input")(createFakeInputEvent("what does this repo do?"), ctxA);
    assert.equal(turnStore.snapshot().session_id, SESSION_A, "the record belongs to A");

    await handlerOf(f, "session_start")(createFakeSessionStartEvent("new"), ctxB);

    // Session B: a `!cmd`. pi fires no `agent_end` for it, so before the session fix it rode along
    // inside A's record. Since the standalone-turn change it never enters the shared store at all:
    // it is posted as its own one-call row immediately, so the store stays exactly as
    // `session_start` left it (empty) — the new contract this case now pins.
    await handlerOf(f, "user_bash")(createFakeUserBashEvent("echo hi"), ctxB);
    assert.deepEqual(
      turnStore.snapshot(),
      { tool_calls: [], results: [] },
      "nothing of A's survived, and the !cmd did not enter the store",
    );

    // B's run ends with nothing recorded, so it posts nothing; the only row is the !cmd's own,
    // under B, with nothing of A's in it.
    handlerOf(f, "agent_end")(createFakeAgentEndEvent([]), ctxB);
    await sleep(60);

    const posted = postedTurns(api);
    assert.equal(posted.length, 1, `exactly one turn log, got ${JSON.stringify(posted)}`);
    assert.equal(posted[0]?.conversation_id, SESSION_B, "posted under the CURRENT session");
    assert.equal(posted[0]?.prompt, "", "and carries no prompt from the previous one");
    // A `!cmd` is recorded under the `bash` tool name, with the adapter's generated `ubash_` id.
    assert.deepEqual(posted[0]?.tools, ["bash"]);
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("session_start drops a pending record rather than posting it", async () => {
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture(api);
  try {
    const ctxA = createFakeCtx({ sessionId: SESSION_A });
    await handlerOf(f, "input")(createFakeInputEvent("half a turn"), ctxA);
    assert.equal(turnStore.snapshot().prompt, "half a turn");

    await handlerOf(f, "session_start")(createFakeSessionStartEvent("new"), createFakeCtx({ sessionId: SESSION_B }));

    // Dropped, not posted: `agent_end` never fired, so nothing says that turn finished, and
    // `session_start` is awaited by pi — the startup path is the wrong place for a POST.
    assert.deepEqual(
      turnStore.snapshot(),
      { tool_calls: [], results: [] },
      "the store is empty, with no session id and no start time carried over",
    );
    await sleep(60);
    assert.deepEqual(turnLogs(api), [], "and nothing was sent on the way out");
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("assistant text cannot resurrect a record session_start dropped", async () => {
  // `agent_end` now reads the model's text off the event rather than the record, so it is the one
  // input to the body that survives a dropped record. It must not make a turn postable on its own:
  // `shouldPostTurn` asks the RECORD whether anything happened, and after a `/new` the answer is no.
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture(api);
  try {
    const ctxA = createFakeCtx({ sessionId: SESSION_A });
    await handlerOf(f, "input")(createFakeInputEvent("half a turn"), ctxA);
    await handlerOf(f, "session_start")(
      createFakeSessionStartEvent("new"),
      createFakeCtx({ sessionId: SESSION_B }),
    );

    handlerOf(f, "agent_end")(
      createFakeAgentEndEvent([
        createFakeAssistantMessage([{ type: "text", text: "an answer belonging to the dropped turn" }]),
      ]),
      createFakeCtx({ sessionId: SESSION_B }),
    );
    await sleep(60);

    assert.deepEqual(turnLogs(api), [], "no record, no row — whatever the event carried");
    assert.deepEqual(turnStore.snapshot(), { tool_calls: [], results: [] });
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("the drop happens even for a session_start that returns early", async () => {
  // No key at all: `session_start` returns before the heartbeat, the presence row and everything
  // else. The record still has to go, because the record is in-memory state and not a network act.
  const api = await startMockApi({ mode: "allow" });
  const homeDir = mkdtempSync(join(tmpdir(), "pi-session-nokey-"));
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  try {
    await createExtension({
      env: {},
      homeDir,
      entrypoint: "pi/0.87.1",
      heartbeatGate: closedGate,
    })(pi as unknown as ExtensionAPI);

    turnStore.recordPrompt("left over", SESSION_A);
    const handler = handlers.get("session_start");
    assert.ok(handler !== undefined);
    await handler(createFakeSessionStartEvent("new"), createFakeCtx({ sessionId: SESSION_B }));
    assert.deepEqual(turnStore.snapshot(), { tool_calls: [], results: [] });
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
    await api.close();
  }
});

test("a ctx whose session id cannot be read does not drop the live record", async () => {
  // `sessionIdOf` answers `""` for a hostile or half-built ctx. An unreadable id is not evidence of
  // a session CHANGE, so it must not be allowed to discard a turn that is mid-flight.
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture(api);
  try {
    const ctxA = createFakeCtx({ sessionId: SESSION_A });
    await handlerOf(f, "input")(createFakeInputEvent("still going"), ctxA);

    const blind = createFakeCtx({ sessionId: SESSION_A });
    blind.sessionManager = {
      getSessionId: () => {
        throw new Error("no session manager");
      },
    };
    await handlerOf(f, "session_start")(createFakeSessionStartEvent("reload"), blind);

    assert.equal(turnStore.snapshot().prompt, "still going", "the record survives an unreadable id");
    turnStore.take();
  } finally {
    f.cleanup();
    await api.close();
  }
});

test("IN-04 a prompt pending in session A never rides session B's tool call", async () => {
  // Handler-level, end to end: the roll-over the `!cmd` case used to exercise. A prompt is recorded
  // in A, the developer types `/new`, and the first tool call in B must not carry A's prompt as the
  // pretool `messages[0].content` — that field is what the gateway writes a block row from.
  const api = await startMockApi({ mode: "allow" });
  const f = await fixture(api);
  try {
    const ctxA = createFakeCtx({ sessionId: SESSION_A });
    const ctxB = createFakeCtx({ sessionId: SESSION_B });
    await handlerOf(f, "input")(createFakeInputEvent("a prompt that belongs to A"), ctxA);
    assert.equal(turnStore.currentPrompt(SESSION_A), "a prompt that belongs to A");

    await handlerOf(f, "session_start")(createFakeSessionStartEvent("new"), ctxB);
    await handlerOf(f, "tool_call")(createFakeToolCallEvent("bash", { command: "ls" }), ctxB);

    const toolBodies = api.requests
      .filter((r) => r.path === "/v1/hooks/pretool")
      .map((r) => r.body as { event_name?: string; conversation_id?: string; messages?: { content?: string }[] })
      .filter((b) => b.event_name === "tool_use");
    assert.equal(toolBodies.length, 1);
    assert.equal(toolBodies[0]?.conversation_id, SESSION_B);
    assert.equal(toolBodies[0]?.messages?.[0]?.content, "", "A's prompt did not cross the session boundary");

    // And the same holds without session_start reaching us first: startTurn's roll-over backstop.
    await handlerOf(f, "input")(createFakeInputEvent("another A prompt"), ctxA);
    await handlerOf(f, "tool_call")(createFakeToolCallEvent("bash", { command: "pwd" }), ctxB);
    const last = api.requests
      .filter((r) => r.path === "/v1/hooks/pretool")
      .map((r) => r.body as { event_name?: string; messages?: { content?: string }[] })
      .filter((b) => b.event_name === "tool_use")
      .at(-1);
    assert.equal(last?.messages?.[0]?.content, "", "a foreign session's prompt is never sent");
    turnStore.take();
  } finally {
    f.cleanup();
    await api.close();
  }
});
