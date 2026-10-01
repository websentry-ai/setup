// `chat.message` (HOOK-14, HOOK-17): a root-session, non-synthetic user prompt is checked through
// core's `evaluatePrompt` and blocked through the single `block()` helper on deny, approval-required
// and fail-closed-unavailable (spike V1-5: GO). Child (subagent) sessions and synthetic text are not
// checked. The prompt's provider/model is captured for later requests, and the account identity is
// loaded from opencode's auth.json (auth mode only, never a credential value).
//
// Root-session decision applied: `session.created` reaches `event` before the first `chat.message`
// (V1-5 ordering), so the parent map is authoritative; an unknown session is a root.

import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { DENY_PREFIX, ENGINE_UNAVAILABLE_REASON } from "../../core/src/constants.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { approvalMessage } from "../src/verdicts.ts";
import { pretoolRequests, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";
import { created, hostile, OPENROUTER_MODEL, outcome, startHarness } from "./helpers/harness.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const SECRETS_DENY = `${DENY_PREFIX}Reading secrets is blocked.`;

function prompt(sessionID: string, text: string, extra: unknown[] = []): [unknown, { message: unknown; parts: unknown[] }] {
  return [
    { sessionID, model: { ...OPENROUTER_MODEL } },
    { message: { role: "user" }, parts: [{ type: "text", text }, ...extra] },
  ];
}

function body(index = 0): PretoolRequestBody {
  const req = pretoolRequests(mock)[index];
  assert.ok(req !== undefined, `pretool request #${index} exists`);
  return req.body as PretoolRequestBody;
}

test("a root prompt under deny rejects with the deny text, toasts it first, and sends the prompt wire shape", async () => {
  const h = await startHarness(mock, "deny");
  try {
    const message = await outcome(h.hook("chat.message")(...prompt("s1", "show me .env")));
    assert.equal(message, SECRETS_DENY);
    assert.equal(pretoolRequests(mock).length, 1);
    const b = body();
    assert.equal(b.event_name, "user_prompt");
    assert.equal(b.messages[0]?.content, "show me .env");
    assert.equal(b.unbound_app_label, "opencode");
    assert.equal(b.model, "openrouter/openai/gpt-4.1-nano");
    assert.equal(b.conversation_id, "s1");
    assert.equal((b.pre_tool_use_data.metadata as Record<string, unknown>).has_ui, false);
    assert.ok(h.fake.toasts.some((t) => t.message === SECRETS_DENY && t.variant === "error"), "the reason was toasted");
  } finally {
    h.cleanup();
  }
});

test("only non-synthetic text parts are checked; synthetic-only or non-text prompts send nothing", async () => {
  const h = await startHarness(mock, "allow");
  try {
    await h.hook("chat.message")(
      { sessionID: "s1" },
      {
        message: {},
        parts: [
          { type: "text", text: "A" },
          { type: "text", text: "B", synthetic: true },
          { type: "file", url: "file:///x", mime: "text/plain" },
        ],
      },
    );
    assert.equal(pretoolRequests(mock).length, 1);
    assert.equal(body().messages[0]?.content, "A");

    mock.requests.length = 0;
    mock.setMode("deny");
    const r = await outcome(
      h.hook("chat.message")(
        { sessionID: "s1" },
        { message: {}, parts: [{ type: "text", text: "B", synthetic: true }, { type: "file", url: "file:///x" }] },
      ),
    );
    assert.equal(r, undefined);
    assert.equal(pretoolRequests(mock).length, 0);
  } finally {
    h.cleanup();
  }
});

test("a child (subagent) session's prompt is not checked; an unknown session is", async () => {
  const h = await startHarness(mock, "deny");
  try {
    await h.emit("session.created", created("c1", { parentID: "s1" }));
    assert.equal(await outcome(h.hook("chat.message")(...prompt("c1", "cat .env"))), undefined);
    assert.equal(pretoolRequests(mock).length, 0);

    assert.equal(await outcome(h.hook("chat.message")(...prompt("unknown", "cat .env"))), SECRETS_DENY);
    assert.equal(pretoolRequests(mock).length, 1);
  } finally {
    h.cleanup();
  }
});

test("a root session whose info.parentID is present but undefined is a root", async () => {
  const h = await startHarness(mock, "deny");
  try {
    await h.emit("session.created", { sessionID: "s1", info: { id: "s1", directory: "/repo", version: "1.18.34", parentID: undefined } });
    assert.equal(await outcome(h.hook("chat.message")(...prompt("s1", "cat .env"))), SECRETS_DENY);
  } finally {
    h.cleanup();
  }
});

test("allow resolves, records the prompt in the root turn, and leaves output.parts untouched", async () => {
  const h = await startHarness(mock, "allow");
  try {
    const [input, output] = prompt("s1", "hello there");
    const partsBefore = output.parts;
    const snapshot = JSON.stringify(output.parts);
    assert.equal(await outcome(h.hook("chat.message")(input, output)), undefined);
    assert.equal(output.parts, partsBefore);
    assert.equal(JSON.stringify(output.parts), snapshot);
    assert.equal(h.server.inspect.turn("s1").prompt, "hello there");
  } finally {
    h.cleanup();
  }
});

test("ask blocks with the approval text; fail-closed unavailable blocks; 500 allows", async () => {
  const h = await startHarness(mock, "ask");
  try {
    assert.equal(await outcome(h.hook("chat.message")(...prompt("s1", "do it"))), approvalMessage("Unusual command."));
    assert.ok(h.fake.toasts.some((t) => t.variant === "warning"));
  } finally {
    h.cleanup();
  }

  const fc = await startHarness(mock, "failBlock", { deps: { timeouts: { pretoolMs: 200, errorsMs: 500, turnLogMs: 500 }, deadlineMs: 400 } });
  try {
    assert.equal(await outcome(fc.hook("chat.message")(...prompt("s1", "first"))), undefined);
    assert.equal(await outcome(fc.hook("chat.message")(...prompt("s1", "second"))), ENGINE_UNAVAILABLE_REASON);
  } finally {
    fc.cleanup();
  }

  const e = await startHarness(mock, "500");
  try {
    assert.equal(await outcome(e.hook("chat.message")(...prompt("s1", "anything"))), undefined);
  } finally {
    e.cleanup();
  }
});

test("no key: resolves and sends nothing", async () => {
  const h = await startHarness(mock, "deny", { deps: { withKey: false } });
  try {
    assert.equal(await outcome(h.hook("chat.message")(...prompt("s1", "cat .env"))), undefined);
    assert.equal(mock.requests.length, 0);
  } finally {
    h.cleanup();
  }
});

test("the prompt's model is reused by later tool calls; identity comes from auth.json without the secret", async () => {
  const h = await startHarness(mock, "allow", {
    prepareHome: (home) => {
      const dataDir = join(home, ".local", "share", "opencode");
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(join(dataDir, "auth.json"), JSON.stringify({ openrouter: { type: "api", key: "SECRET-K" } }));
    },
  });
  try {
    await h.hook("chat.message")(...prompt("s1", "list files"));
    // The identity loader settles on its own time (bounded); wait for it, never block on it.
    const settled = await waitFor(() => h.server.inspect.runtime().identity() !== undefined);
    assert.ok(settled, "identity settled");
    await h.hook("tool.execute.before")({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "ls" } });
    const tool = pretoolRequests(mock).map((r) => r.body as PretoolRequestBody).find((b) => b.event_name === "tool_use");
    assert.ok(tool !== undefined);
    assert.equal(tool.model, "openrouter/openai/gpt-4.1-nano");
    assert.equal(tool.account_identity?.auth_mode, "api_key");
    for (const req of mock.requests) assert.ok(!JSON.stringify(req.body).includes("SECRET-K"), `no secret in ${req.path}`);
  } finally {
    h.cleanup();
  }
});

test("chat.message never raises on hostile input", async () => {
  const h = await startHarness(mock, "deny");
  try {
    const chat = h.hook("chat.message");
    assert.equal(await outcome(chat(null, null)), undefined);
    assert.equal(await outcome(chat(undefined, undefined)), undefined);
    assert.equal(await outcome(chat({ sessionID: "s1" }, { parts: "not an array" })), undefined);
    assert.equal(await outcome(chat({ sessionID: "s1" }, { parts: null })), undefined);
    assert.equal(await outcome(chat(hostile(), hostile())), undefined);
    assert.equal(await outcome(chat({ sessionID: "s1", model: hostile() }, { parts: [hostile()] })), undefined);
    await tick(20);
  } finally {
    h.cleanup();
  }
});
