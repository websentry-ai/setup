// Session lifecycle on the `event` bus (HOOK-16, HOOK-17, RES-04 parity): a heartbeat with the
// opencode version on `session.created` (root only, once per directory per TTL), assistant text from
// `message.part.updated`, one turn log per root turn on `session.idle` (subagent calls rolled in,
// child idles post nothing), and `session.deleted` releasing state without posting.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import type { TurnLogBody } from "../../core/src/turnLog.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { CapturedRequest, MockApi } from "../../core/test/helpers/mockApi.ts";
import { pretoolRequests, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";
import { created, hostile, OPENROUTER_MODEL, outcome, startHarness } from "./helpers/harness.ts";
import type { Harness } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const TURNLOG_PATH = "/v1/hooks/opencode";

function heartbeats(): PretoolRequestBody[] {
  return pretoolRequests(mock)
    .map((r) => r.body as PretoolRequestBody)
    .filter((b) => b.event_name === "session_start");
}

function turnLogs(): CapturedRequest[] {
  return mock.requests.filter((r) => r.path === TURNLOG_PATH);
}

async function promptAndBash(h: Harness, sessionID: string, callID: string, text = "hi"): Promise<void> {
  await h.hook("chat.message")({ sessionID, model: { ...OPENROUTER_MODEL } }, { message: {}, parts: [{ type: "text", text }] });
  await h.hook("tool.execute.before")({ tool: "bash", sessionID, callID }, { args: { command: "ls" } });
  await h.hook("tool.execute.after")({ tool: "bash", sessionID, callID, args: { command: "ls" } }, { title: "", output: "out", metadata: {} });
}

test("a root session.created sends one heartbeat with the opencode version; later calls use it", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("session.created", created("s1", { directory: "/repo", version: "1.18.34" }));
    assert.ok(await waitFor(() => heartbeats().length === 1));
    const hb = heartbeats()[0] as PretoolRequestBody;
    assert.equal((hb.pre_tool_use_data.metadata as Record<string, unknown>).opencode_version, "1.18.34");
    assert.equal(hb.client_entrypoint, "opencode/1.18.34");
    assert.equal(hb.unbound_app_label, "opencode");
    assert.equal(hb.conversation_id, "s1");

    await h.hook("tool.execute.before")({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "ls" } });
    const tool = pretoolRequests(mock).map((r) => r.body as PretoolRequestBody).find((b) => b.event_name === "tool_use");
    assert.equal(tool?.client_entrypoint, "opencode/1.18.34");

    // Same directory within the TTL: no second heartbeat. Another directory: one more. A child: none.
    await h.emit("session.created", created("s2", { directory: "/repo" }));
    await h.emit("session.created", created("c1", { directory: "/repo", parentID: "s1" }));
    await tick(100);
    assert.equal(heartbeats().length, 1);
    await h.emit("session.created", created("s3", { directory: "/other" }));
    assert.ok(await waitFor(() => heartbeats().length === 2));
    await h.emit("session.created", created("c2", { directory: "/third", parentID: "s3" }));
    await tick(100);
    assert.equal(heartbeats().length, 2, "a child session never heartbeats");
  } finally {
    h.cleanup();
  }
});

test("an unsafe host version is not used: entrypoint and metadata say unknown", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("session.created", created("s1", { version: "1.18.34; rm" }));
    assert.ok(await waitFor(() => heartbeats().length === 1));
    const hb = heartbeats()[0] as PretoolRequestBody;
    assert.equal(hb.client_entrypoint, "opencode/unknown");
    assert.equal((hb.pre_tool_use_data.metadata as Record<string, unknown>).opencode_version, "unknown");
  } finally {
    h.cleanup();
  }
});

test("session.idle posts one turn log with the prompt, the tool call and the latest assistant text", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("session.created", created("s1"));
    await promptAndBash(h, "s1", "c1", "hi there");
    await h.emit("message.updated", { sessionID: "s1", info: { id: "m2", role: "assistant", sessionID: "s1" } });
    const textPart = (id: string, text: string, extra: Record<string, unknown> = {}) => ({
      sessionID: "s1",
      part: { id, sessionID: "s1", messageID: "m2", type: "text", text, ...extra },
    });
    await h.emit("message.part.updated", textPart("p1", "Hel"));
    await h.emit("message.part.updated", textPart("p1", "Hello world"));
    await h.emit("message.part.updated", textPart("p2", "SYNTHETIC NOTE", { synthetic: true }));
    // A user message's text part is never assistant text.
    await h.emit("message.updated", { sessionID: "s1", info: { id: "m1", role: "user", sessionID: "s1" } });
    await h.emit("message.part.updated", { sessionID: "s1", part: { id: "p0", sessionID: "s1", messageID: "m1", type: "text", text: "USER TEXT" } });

    await h.emit("session.idle", { sessionID: "s1" });
    assert.ok(await waitFor(() => turnLogs().length === 1));
    const b = turnLogs()[0]?.body as TurnLogBody;
    assert.equal(b.conversation_id, "s1");
    assert.equal(b.model, "auto");
    assert.equal(b.cwd, "/repo");
    const raw = JSON.stringify(b);
    assert.ok(b.messages.some((m) => m.role === "user" && m.content === "hi there"));
    assert.ok(b.messages.some((m) => m.role === "assistant" && m.content === "Hello world"), raw);
    assert.ok(raw.includes('"tool_use_id":"c1"'));
    assert.ok(!raw.includes("SYNTHETIC NOTE"));
    assert.ok(!raw.includes("USER TEXT"));
    assert.ok(!raw.includes('"out"'), "tool output never leaves except as a hash");

    await h.emit("session.idle", { sessionID: "s1" });
    await tick(100);
    assert.equal(turnLogs().length, 1, "a second idle with nothing new posts nothing");
  } finally {
    h.cleanup();
  }
});

test("a child session's calls roll up into the root turn; the child's idle posts nothing", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("session.created", created("s1"));
    await h.hook("chat.message")({ sessionID: "s1" }, { message: {}, parts: [{ type: "text", text: "root prompt" }] });
    await h.emit("session.created", created("c1", { parentID: "s1" }));
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: "c1", callID: "child_call" }, { args: { command: "ls" } });
    await h.hook("tool.execute.after")({ tool: "bash", sessionID: "c1", callID: "child_call", args: { command: "ls" } }, { title: "", output: "x", metadata: {} });

    await h.emit("session.idle", { sessionID: "c1" });
    await tick(100);
    assert.equal(turnLogs().length, 0);

    await h.emit("session.idle", { sessionID: "s1" });
    assert.ok(await waitFor(() => turnLogs().length === 1));
    const raw = JSON.stringify(turnLogs()[0]?.body);
    assert.ok(raw.includes('"tool_use_id":"child_call"'), raw);
    assert.ok(raw.includes("root prompt"));
  } finally {
    h.cleanup();
  }
});

test("session.deleted releases a pending turn without posting it", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("session.created", created("s1"));
    await promptAndBash(h, "s1", "c1");
    assert.equal(h.server.inspect.turn("s1").prompt, "hi");
    await h.emit("session.deleted", { sessionID: "s1", info: { id: "s1", directory: "/repo", version: "1.18.34" } });
    await tick(100);
    assert.equal(turnLogs().length, 0);
    const turn = h.server.inspect.turn("s1");
    assert.equal(turn.prompt, undefined);
    assert.equal(turn.tool_calls.length, 0);
    await h.emit("session.idle", { sessionID: "s1" });
    await tick(50);
    assert.equal(turnLogs().length, 0);
  } finally {
    h.cleanup();
  }
});

test("a failing or hanging turn-log route never raises", async () => {
  const h = await startHarness(mock, "allow", { deps: { timeouts: { pretoolMs: 500, errorsMs: 300, turnLogMs: 150 } } });
  try {
    mock.setTurnLogMode("401");
    await promptAndBash(h, "s1", "c1");
    assert.equal(await outcome(h.emit("session.idle", { sessionID: "s1" })), undefined);
    assert.ok(await waitFor(() => turnLogs().length === 1));

    mock.setTurnLogMode("hang");
    await promptAndBash(h, "s1", "c2");
    const started = Date.now();
    assert.equal(await outcome(h.emit("session.idle", { sessionID: "s1" })), undefined);
    assert.ok(Date.now() - started < 100, "idle does not wait for the post");
    await tick(300);
  } finally {
    mock.setTurnLogMode("ok");
    h.cleanup();
  }
});

test("a latched key sends no heartbeat and no turn log", async () => {
  const h = await startHarness(mock, "401");
  try {
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: "s1", callID: "a" }, { args: { command: "ls" } });
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: "s1", callID: "b" }, { args: { command: "ls" } });
    assert.equal(h.server.inspect.runtime().recordingActive(), false);
    mock.requests.length = 0;
    await h.emit("session.created", created("s9"));
    await h.hook("chat.message")({ sessionID: "s9" }, { message: {}, parts: [{ type: "text", text: "x" }] });
    await h.emit("session.idle", { sessionID: "s9" });
    await tick(100);
    assert.equal(heartbeats().length, 0);
    assert.equal(turnLogs().length, 0);
  } finally {
    h.cleanup();
  }
});

test("every lifecycle event type resolves on null or hostile properties", async () => {
  const h = await startHarness(mock, "allow");
  try {
    for (const type of ["session.created", "session.idle", "session.deleted", "message.updated", "message.part.updated"]) {
      for (const properties of [null, undefined, 42, {}, hostile(), { sessionID: "s1", info: hostile() }, { sessionID: "s1", part: hostile() }]) {
        assert.equal(await outcome(h.emit(type, properties)), undefined, `${type}`);
      }
    }
  } finally {
    h.cleanup();
  }
});
