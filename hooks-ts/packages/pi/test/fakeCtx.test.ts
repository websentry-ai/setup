// Shape assertions for the event doubles Waves 3-4 build on.
//
// These live in the *pi* package on purpose: the `test:unit` glob already matches
// `packages/pi/test/*.test.ts`, so no `packages/core/test/*` file has to import across the
// workspace boundary to reach them.
//
// A double that is wrong in the same direction as the code under test proves nothing. Every field
// asserted here is transcribed from pi 0.87.1's own `dist/core/extensions/types.d.ts`, with the
// line range cited beside each factory in `helpers/fakeCtx.ts`. The three facts most likely to be
// mis-remembered, and therefore asserted hardest:
//
//   * `UserBashEvent` has NO id field (`:710-719`) - hence the generated `ubash_<ulid>`.
//   * `toolName` lives on each `ToolResultEvent` VARIANT, not on the base (`:791-836`).
//   * `InputSource` is `"interactive" | "rpc" | "extension"` (`:721`) - there is no slash/system flag.

import test from "node:test";
import assert from "node:assert/strict";

import {
  createFakeAgentEndEvent,
  createFakeClock,
  createFakeInputEvent,
  createFakeSessionStartEvent,
  createFakeToolResultEvent,
  createFakeUserBashEvent,
} from "./helpers/fakeCtx.ts";

// --- user_bash (HOOK-04) ---------------------------------------------------------------------

test("createFakeUserBashEvent yields exactly pi's four fields and no id", () => {
  const event = createFakeUserBashEvent("cat .env", { excludeFromContext: false, cwd: "/tmp/x" });

  assert.deepEqual(Object.keys(event).sort(), ["command", "cwd", "excludeFromContext", "type"]);
  assert.equal(event.type, "user_bash");
  assert.equal(event.command, "cat .env");
  assert.equal(event.excludeFromContext, false);
  assert.equal(event.cwd, "/tmp/x");

  // The absence is the point: with no id on the event, the adapter must generate `ubash_<ulid>`.
  assert.ok(!("id" in event), "UserBashEvent carries no id in pi 0.87.1");
  assert.ok(!("toolCallId" in event), "UserBashEvent carries no toolCallId either");
});

test("createFakeUserBashEvent models !! via excludeFromContext and defaults it to false", () => {
  assert.equal(createFakeUserBashEvent("echo hi").excludeFromContext, false);
  assert.equal(createFakeUserBashEvent("echo hi", { excludeFromContext: true }).excludeFromContext, true);
  // cwd is on the event, so a handler never needs ctx.cwd here.
  assert.equal(typeof createFakeUserBashEvent("echo hi").cwd, "string");
});

// --- input (HOOK-05) -------------------------------------------------------------------------

test("createFakeInputEvent defaults source to interactive and omits images unless asked", () => {
  const plain = createFakeInputEvent("hi");
  assert.equal(plain.type, "input");
  assert.equal(plain.text, "hi");
  assert.equal(plain.source, "interactive");
  assert.ok(!("images" in plain), "images must be absent, not an empty array");
  assert.ok(!("streamingBehavior" in plain), "streamingBehavior is undefined when idle");

  const explicit = createFakeInputEvent("hi", { source: "rpc" });
  assert.equal(explicit.source, "rpc");

  const withImages = createFakeInputEvent("look", {
    images: [{ type: "image", data: "aGk=", mimeType: "image/png" }],
  });
  assert.ok(Array.isArray(withImages.images));
  assert.equal(withImages.images?.length, 1);
  assert.equal(withImages.images?.[0]?.mimeType, "image/png");
});

test("createFakeInputEvent covers all three InputSource values and steering", () => {
  for (const source of ["interactive", "rpc", "extension"] as const) {
    assert.equal(createFakeInputEvent("x", { source }).source, source);
  }
  assert.equal(createFakeInputEvent("x", { streamingBehavior: "steer" }).streamingBehavior, "steer");
});

// --- tool_result (HOOK-06) -------------------------------------------------------------------

test("createFakeToolResultEvent puts toolName on the object alongside the base fields", () => {
  const event = createFakeToolResultEvent("bash", {
    content: [{ type: "text", text: "out" }],
    isError: false,
  });

  // toolName is on the variant, not the base - so the local structural type must declare it.
  assert.equal(event.toolName, "bash");
  assert.equal(event.type, "tool_result");
  assert.equal(typeof event.toolCallId, "string");
  assert.ok(event.toolCallId.length > 0);
  assert.equal(typeof event.input, "object");
  assert.deepEqual(event.content, [{ type: "text", text: "out" }]);
  assert.equal(event.isError, false);
  assert.ok(!("usage" in event), "usage is optional and absent by default");
});

test("createFakeToolResultEvent carries an error result, image content and usage when asked", () => {
  const event = createFakeToolResultEvent("read", {
    toolCallId: "call_1",
    input: { path: "/tmp/x" },
    content: [{ type: "image", data: "aGk=", mimeType: "image/png" }],
    isError: true,
    usage: { input: 1, output: 2 },
  });

  assert.equal(event.toolCallId, "call_1");
  assert.deepEqual(event.input, { path: "/tmp/x" });
  assert.equal(event.isError, true);
  assert.equal(event.content[0]?.type, "image");
  assert.deepEqual(event.usage, { input: 1, output: 2 });
});

// --- agent_end (RES-04) ----------------------------------------------------------------------

test("createFakeAgentEndEvent wraps only the run's new messages", () => {
  const messages = [{ role: "assistant", content: "done", model: "openrouter/openai/gpt-4.1-nano" }];
  const event = createFakeAgentEndEvent(messages);

  assert.deepEqual(Object.keys(event).sort(), ["messages", "type"]);
  assert.equal(event.type, "agent_end");
  assert.deepEqual(event.messages, messages);

  // `messages` is newMessages: it never contains the user prompt, which is why the turn record
  // has to capture the prompt from the `input` handler instead.
  assert.deepEqual(createFakeAgentEndEvent([]).messages, []);
});

// --- session_start (RES-05) ------------------------------------------------------------------

test("createFakeSessionStartEvent covers every reason and the optional previousSessionFile", () => {
  const event = createFakeSessionStartEvent("new");
  assert.deepEqual(Object.keys(event).sort(), ["reason", "type"]);
  assert.equal(event.type, "session_start");
  assert.equal(event.reason, "new");
  assert.ok(!("previousSessionFile" in event));

  for (const reason of ["startup", "reload", "new", "resume", "fork"] as const) {
    assert.equal(createFakeSessionStartEvent(reason).reason, reason);
  }

  const resumed = createFakeSessionStartEvent("resume", { previousSessionFile: "/tmp/prev.json" });
  assert.equal(resumed.previousSessionFile, "/tmp/prev.json");
});

// --- the injectable clock (WR-02 / RES-03) ---------------------------------------------------

test("createFakeClock is pure and advances only when told, with no timers", () => {
  const clock = createFakeClock(1_000);

  assert.equal(clock.now(), 1_000);
  assert.equal(clock.now(), 1_000, "now() must be pure - two reads without an advance are equal");

  clock.advance(300_000);
  assert.equal(clock.now(), 301_000);

  clock.advance(1);
  assert.equal(clock.now(), 301_001);

  // A default start keeps a test from having to pick a number when it only cares about deltas.
  const defaulted = createFakeClock();
  assert.equal(typeof defaulted.now(), "number");
  const before = defaulted.now();
  defaulted.advance(5);
  assert.equal(defaulted.now() - before, 5);
});

// --- the standing no-pi-imports rule ----------------------------------------------------------

test("the helper never names the pi package, in an import or in prose", async () => {
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const source = readFileSync(join(import.meta.dirname, "helpers", "fakeCtx.ts"), "utf8");

  // Split so this assertion cannot match itself.
  const vendor = ["@earendil", "-works"].join("");
  assert.equal(source.includes(vendor), false, "fakeCtx must stay import-free of the pi package");
});
