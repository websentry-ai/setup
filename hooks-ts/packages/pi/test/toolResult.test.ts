// HOOK-06 at the pi boundary. Two guarantees, and both are assertions about what does NOT happen.
//
//   1. The handler returns `=== undefined`. `agent-session.js:265-294` folds any defined field of the
//      handler result back into the real tool result the model reads, so `{}` is safe only by
//      accident and `{isError:false}` would rewrite a genuine error. A truthiness check would pass
//      for `{}` — hence `assert.strictEqual(result, undefined)` everywhere below.
//   2. No raw output is retained. The marker is written into the tool content and then grepped out
//      of the store's serialised snapshot.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { MAX_HASH_BYTES } from "../../core/src/constants.ts";
import { createTurnStore } from "../../core/src/turn.ts";
import { recordToolResult } from "../src/toolResult.ts";
import { createFakeToolResultEvent } from "./helpers/fakeCtx.ts";

const MARKER = "SLACK_BOT_TOKEN=xoxb-never-recorded";
const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

test("the handler returns undefined for an ordinary result", () => {
  const store = createTurnStore();
  const event = createFakeToolResultEvent("bash", { content: [{ type: "text", text: "ok" }] });

  const result = recordToolResult(event, store);

  assert.strictEqual(result, undefined, "any defined key would rewrite the real tool result");
});

test("the handler returns undefined for an error result, an empty result and a malformed event", () => {
  const store = createTurnStore();

  assert.strictEqual(
    recordToolResult(createFakeToolResultEvent("bash", { isError: true }), store),
    undefined,
  );
  assert.strictEqual(
    recordToolResult(createFakeToolResultEvent("read", { content: [] }), store),
    undefined,
  );
  // Genuinely malformed: a third-party `registerTool` can deliver anything here.
  assert.strictEqual(recordToolResult({} as never, store), undefined);
  assert.strictEqual(recordToolResult(null as never, store), undefined);
  assert.strictEqual(
    recordToolResult({ type: "tool_result", content: "not an array" } as never, store),
    undefined,
  );
});

test("a throwing store still yields undefined and no exception escapes", () => {
  const exploding = {
    recordResult() {
      throw new Error("store on fire");
    },
  } as never;

  let result: unknown = "unset";
  assert.doesNotThrow(() => {
    result = recordToolResult(createFakeToolResultEvent("bash"), exploding);
  }, "emitToolResult reports handler errors, but a silent no-op is the honest outcome");
  assert.strictEqual(result, undefined);
});

test("the result is recorded as name, isError, digest and byte count", () => {
  const store = createTurnStore();
  const event = createFakeToolResultEvent("read", {
    toolCallId: "call_read_1",
    content: [{ type: "text", text: "file contents" }],
  });

  recordToolResult(event, store);

  assert.deepEqual(store.snapshot().results, [
    {
      tool_name: "read",
      tool_use_id: "call_read_1",
      is_error: false,
      content_sha256: sha256("text:file contents"),
      content_bytes: Buffer.byteLength("text:file contents", "utf8"),
    },
  ]);
});

test("isError rides through verbatim", () => {
  const store = createTurnStore();
  recordToolResult(createFakeToolResultEvent("bash", { isError: true }), store);
  assert.equal(store.snapshot().results[0]?.is_error, true);
});

test("the raw tool output never reaches the record (T-09-10)", () => {
  const store = createTurnStore();
  const event = createFakeToolResultEvent("bash", {
    input: { command: `echo ${MARKER}` },
    content: [
      { type: "text", text: `stdout:\n${MARKER}\n`, textSignature: "sig" },
      { type: "image", data: Buffer.from(MARKER).toString("base64"), mimeType: "image/png" },
    ],
  });

  recordToolResult(event, store);

  const serialised = JSON.stringify(store.snapshot());
  assert.equal(serialised.includes(MARKER), false, `raw output leaked into ${serialised}`);
  assert.equal(serialised.includes("echo "), false, "and the tool input is not recorded either");
  assert.equal(typeof store.snapshot().results[0]?.content_sha256, "string");
});

test("an oversized result is counted, flagged and not hashed", () => {
  const store = createTurnStore();
  const event = createFakeToolResultEvent("bash", {
    content: [{ type: "text", text: "z".repeat(MAX_HASH_BYTES + 1) }],
  });

  recordToolResult(event, store);

  const [only] = store.snapshot().results;
  assert.equal(only?.hash_skipped, true);
  assert.equal(only?.content_sha256, undefined);
  assert.ok((only?.content_bytes ?? 0) > MAX_HASH_BYTES);
});

test("a result does not make the turn postable on its own", () => {
  // The record exists to describe a turn somebody started; a result with no call is not one.
  const store = createTurnStore();
  recordToolResult(createFakeToolResultEvent("bash"), store);
  assert.equal(store.isEmpty(), true);
});

test("two results are recorded in order, one entry each", () => {
  const store = createTurnStore();
  recordToolResult(createFakeToolResultEvent("bash", { toolCallId: "c1" }), store);
  recordToolResult(createFakeToolResultEvent("read", { toolCallId: "c2", isError: true }), store);

  const results = store.snapshot().results;
  assert.equal(results.length, 2);
  assert.equal(results[0]?.tool_use_id, "c1");
  assert.equal(results[1]?.tool_use_id, "c2");
  assert.equal(results[1]?.is_error, true);
});
