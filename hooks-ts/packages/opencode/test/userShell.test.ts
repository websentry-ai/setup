// User `!cmd` (HOOK-19). Branch taken: **GO** (spike V1-7 PROVEN on the `POST /session/:id/shell`
// route: the bash part with `state.input.command` reaches `event` before `shell.env` in 6/6 repeats,
// and a raise from `shell.env` prevented the spawn in 6/6). The user command is recovered from the
// persisted bash part and checked through core's `evaluateToolCall`; a model `bash` call (which
// passed `tool.execute.before`) is never checked twice. Caveats are in docs/OPENCODE.md.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENY_PREFIX, USER_BASH_ID_PREFIX } from "../../core/src/constants.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { SIGNAL_USER_SHELL_UNCHECKED } from "../src/constants.ts";
import { pretoolRequests, signalsOf, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";
import { hostile, outcome, startHarness } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const S = "ses_root";
const SECRETS_DENY = `${DENY_PREFIX}Reading secrets is blocked.`;

function bashPart(callID: string, status: string, command: string, sessionID = S): unknown {
  return {
    sessionID,
    part: {
      id: `prt_${callID}`,
      sessionID,
      messageID: "msg_u",
      type: "tool",
      tool: "bash",
      callID,
      state: { status, input: { command } },
    },
  };
}

test("shell.env is registered (V1-7 GO)", async () => {
  const h = await startHarness(mock, "allow");
  try {
    assert.equal(typeof h.hooks["shell.env"], "function");
  } finally {
    h.cleanup();
  }
});

test("a user !cmd seen as a bash part with no before-hook is checked and blocked in shell.env", async () => {
  const h = await startHarness(mock, "deny");
  try {
    await h.emit("message.part.updated", bashPart("u1", "running", "cat .env"));
    const env: Record<string, string> = {};
    const output = { env };
    const message = await outcome(h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "u1" }, output));
    assert.equal(message, SECRETS_DENY);
    const reqs = pretoolRequests(mock);
    assert.equal(reqs.length, 1);
    const b = reqs[0]?.body as PretoolRequestBody;
    assert.equal(b.pre_tool_use_data.tool_name, "bash");
    assert.equal(b.pre_tool_use_data.command, "cat .env");
    assert.ok(String(b.pre_tool_use_data.tool_use_id).startsWith(USER_BASH_ID_PREFIX));
    assert.equal(b.conversation_id, S);
    assert.equal(output.env, env, "output.env is the same object");
    assert.deepEqual(env, {}, "output.env is never modified");
  } finally {
    h.cleanup();
  }
});

test("an allowed user !cmd resolves and leaves env untouched", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("message.part.updated", bashPart("u2", "running", "ls"));
    const env: Record<string, string> = { A: "1" };
    assert.equal(await outcome(h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "u2" }, { env })), undefined);
    assert.equal(pretoolRequests(mock).length, 1);
    assert.deepEqual(env, { A: "1" });
  } finally {
    h.cleanup();
  }
});

test("a model bash call (before-hook seen) is never checked a second time in shell.env", async () => {
  const h = await startHarness(mock, "allow");
  try {
    // Model parts are published before tool.execute.before runs.
    await h.emit("message.part.updated", bashPart("m1", "pending", ""));
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: S, callID: "m1" }, { args: { command: "ls" } });
    await h.emit("message.part.updated", bashPart("m1", "running", "ls"));
    assert.equal(pretoolRequests(mock).length, 1);
    mock.setMode("deny");
    assert.equal(await outcome(h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "m1" }, { env: {} })), undefined);
    assert.equal(pretoolRequests(mock).length, 1, "no second pretool request");
  } finally {
    h.cleanup();
  }
});

test("shell.env for a callID with no stashed part resolves and reports user_shell_unchecked (no_part)", async () => {
  const h = await startHarness(mock, "deny");
  try {
    assert.equal(await outcome(h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "zz" }, { env: {} })), undefined);
    assert.equal(pretoolRequests(mock).length, 0);
    assert.ok(await waitFor(() => signalsOf(mock, SIGNAL_USER_SHELL_UNCHECKED).length === 1));
    const entry = (signalsOf(mock, SIGNAL_USER_SHELL_UNCHECKED)[0]?.body as { errors: Array<Record<string, unknown>> })
      .errors[0];
    assert.ok(JSON.stringify(entry).includes("no_part"));
  } finally {
    h.cleanup();
  }
});

test("the stashed command is consumed: a second shell.env for the same callID is not re-checked", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.emit("message.part.updated", bashPart("u3", "running", "ls"));
    await h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "u3" }, { env: {} });
    await h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "u3" }, { env: {} });
    assert.equal(pretoolRequests(mock).length, 1);
  } finally {
    h.cleanup();
  }
});

test("no key: shell.env resolves with zero requests", async () => {
  const h = await startHarness(mock, "deny", { deps: { withKey: false } });
  try {
    await h.emit("message.part.updated", bashPart("u4", "running", "cat .env"));
    assert.equal(await outcome(h.hook("shell.env")({ cwd: "/repo", sessionID: S, callID: "u4" }, { env: {} })), undefined);
    await tick();
    assert.equal(mock.requests.length, 0);
  } finally {
    h.cleanup();
  }
});

test("shell.env never raises on hostile input", async () => {
  const h = await startHarness(mock, "deny");
  try {
    const hook = h.hook("shell.env");
    for (const [input, output] of [
      [null, null],
      [undefined, undefined],
      [hostile(), hostile()],
      [{ sessionID: 5, callID: {} }, { env: null }],
    ] as const) {
      assert.equal(await outcome(hook(input, output)), undefined);
    }
  } finally {
    h.cleanup();
  }
});
