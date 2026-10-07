// `tool.execute.after` and the error-path audit (HOOK-15), and args-digest tamper detection
// (HOOK-18). Every tool result is audited hash-only, exactly once per call: successes from the
// after-hook, failed and blocked calls from `message.part.updated` error parts (no after-hook fires
// for them, spike V1-1). A call whose args changed after our check is reported, never blocked.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { hashContent } from "../../core/src/turn.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { SIGNAL_ARGS_CHANGED } from "../src/constants.ts";
import { signalsOf, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";
import { hostile, outcome, startHarness } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const S = "ses_root";

function toolPart(callID: string, tool: string, state: Record<string, unknown>, sessionID = S): unknown {
  return { sessionID, part: { id: `prt_${callID}`, sessionID, messageID: "msg_a", type: "tool", tool, callID, state } };
}

test("a successful bash call is audited once, hash-only", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "c1" }, { args: { command: "printf greeting" } });
    const r = await outcome(
      h.hook("tool.execute.after")(
        { tool: "bash", sessionID: S, callID: "c1", args: { command: "printf greeting" } },
        { title: "echo", output: "hello", metadata: {} },
      ),
    );
    assert.equal(r, undefined);
    const turn = h.server.inspect.turn(S);
    assert.equal(turn.results.length, 1);
    const expected = hashContent([{ type: "text", text: "hello" }]);
    assert.deepEqual(turn.results[0], {
      tool_name: "bash",
      tool_use_id: "c1",
      is_error: false,
      content_sha256: expected.content_sha256,
      content_bytes: expected.content_bytes,
    });
    assert.ok(!JSON.stringify(turn).includes("hello"), "the raw output is not in the record");
  } finally {
    h.cleanup();
  }
});

test("an MCP CallToolResult output is hashed over its content parts", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.hook("tool.execute.after")(
      { tool: "my_server_list", sessionID: S, callID: "m1", args: {} },
      { title: "", output: { content: [{ type: "text", text: "x" }], isError: false }, metadata: {} },
    );
    const turn = h.server.inspect.turn(S);
    assert.equal(turn.results.length, 1);
    assert.equal(turn.results[0]?.content_sha256, hashContent([{ type: "text", text: "x" }]).content_sha256);
  } finally {
    h.cleanup();
  }
});

test("an error tool part is audited as an error, and each callID yields exactly one result", async () => {
  const h = await startHarness(mock, "allow");
  try {
    const err = "Blocked by Unbound policy: no";
    await h.emit("message.part.updated", toolPart("c9", "read", { status: "error", error: err, input: {} }));
    let turn = h.server.inspect.turn(S);
    assert.equal(turn.results.length, 1);
    assert.equal(turn.results[0]?.is_error, true);
    assert.equal(turn.results[0]?.tool_use_id, "c9");
    assert.equal(turn.results[0]?.content_sha256, hashContent([{ type: "text", text: err }]).content_sha256);

    await h.emit("message.part.updated", toolPart("c9", "read", { status: "error", error: err, input: {} }));
    await h.hook("tool.execute.after")({ tool: "read", sessionID: S, callID: "c9", args: {} }, { title: "", output: "late", metadata: {} });
    turn = h.server.inspect.turn(S);
    assert.equal(turn.results.length, 1, "still one result for c9");

    // Running / completed parts are not audited from events (the after-hook does that).
    await h.emit("message.part.updated", toolPart("c10", "bash", { status: "running", input: { command: "ls" } }));
    await h.emit("message.part.updated", toolPart("c10", "bash", { status: "completed", input: {}, output: "x" }));
    assert.equal(h.server.inspect.turn(S).results.length, 1);
  } finally {
    h.cleanup();
  }
});

test("args mutated after the check are reported as args_changed_after_check, not blocked", async () => {
  const h = await startHarness(mock, "allow", { deps: { signalIntervalMs: 0 } });
  try {
    const output = { args: { command: "ls" } as Record<string, unknown> };
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "t1" }, output);
    output.args.command = "rm -rf ~";
    const r = await outcome(h.hook("tool.execute.after")({ tool: "bash", sessionID: S, callID: "t1", args: output.args }, { title: "", output: "", metadata: {} }));
    assert.equal(r, undefined);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_ARGS_CHANGED).length === 1));
  } finally {
    h.cleanup();
  }
});

test("unmutated args and calls with no stored digest report nothing", async () => {
  const h = await startHarness(mock, "allow", { deps: { signalIntervalMs: 0 } });
  try {
    const output = { args: { command: "ls" } };
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "u1" }, output);
    await h.hook("tool.execute.after")({ tool: "bash", sessionID: S, callID: "u1", args: output.args }, { title: "", output: "", metadata: {} });
    await h.hook("tool.execute.after")({ tool: "bash", sessionID: S, callID: "never-checked", args: { command: "x" } }, { title: "", output: "", metadata: {} });
    await tick(100);
    assert.equal(signalsOf(mock, SIGNAL_ARGS_CHANGED).length, 0);
  } finally {
    h.cleanup();
  }
});

test("no key, or a latched key: nothing is recorded", async () => {
  const nokey = await startHarness(mock, "allow", { deps: { withKey: false } });
  try {
    await nokey.hook("tool.execute.after")({ tool: "bash", sessionID: S, callID: "c1", args: {} }, { title: "", output: "x", metadata: {} });
    await nokey.emit("message.part.updated", toolPart("c2", "read", { status: "error", error: "e", input: {} }));
    assert.equal(nokey.server.inspect.turn(S).results.length, 0);
    assert.equal(mock.requests.length, 0);
  } finally {
    nokey.cleanup();
  }

  const latched = await startHarness(mock, "401");
  try {
    // Two consecutive 401s latch a fail-open session (core keyState).
    await latched.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "c0" }, { args: { command: "ls" } });
    await latched.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "c1" }, { args: { command: "ls" } });
    assert.equal(latched.server.inspect.runtime().recordingActive(), false, "the key latched");
    await latched.hook("tool.execute.after")({ tool: "bash", sessionID: S, callID: "c1", args: {} }, { title: "", output: "x", metadata: {} });
    await latched.emit("message.part.updated", toolPart("c2", "read", { status: "error", error: "e", input: {} }));
    assert.equal(latched.server.inspect.turn(S).results.length, 0);
  } finally {
    latched.cleanup();
  }
});

test("the after-hook and the event handler never raise or reject", async () => {
  const h = await startHarness(mock, "allow");
  try {
    const afterHook = h.hook("tool.execute.after");
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    const raisingOutput = Object.defineProperty({}, "output", {
      get() {
        throw new Error("getter");
      },
    });
    for (const [input, output] of [
      [null, null],
      [undefined, undefined],
      [42, "x"],
      [{ tool: "bash", sessionID: S, callID: "z1", args: {} }, raisingOutput],
      [{ tool: "bash", sessionID: S, callID: "z2", args: cyclic }, { output: cyclic }],
      [hostile(), hostile()],
      [{ tool: "bash", sessionID: S, callID: "z3", args: hostile() }, { output: { content: [hostile()] } }],
    ] as Array<[unknown, unknown]>) {
      assert.equal(await outcome(afterHook(input, output)), undefined);
    }
    const ev = h.hook("event");
    for (const input of [
      null,
      undefined,
      {},
      { event: null },
      { event: { type: "something.unknown", properties: {} } },
      { event: { type: "message.part.updated", properties: hostile() } },
      { event: { type: "message.part.updated", properties: { part: hostile() } } },
      { event: hostile() },
      hostile(),
    ]) {
      assert.equal(await outcome(ev(input)), undefined);
    }
  } finally {
    h.cleanup();
  }
});
