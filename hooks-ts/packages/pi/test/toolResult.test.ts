// HOOK-06 at the pi boundary. Two guarantees, and both are assertions about what does NOT happen.
//
//   1. The handler returns `=== undefined`. `agent-session.js:265-294` folds any defined field of the
//      handler result back into the real tool result the model reads, so `{}` is safe only by
//      accident and `{isError:false}` would rewrite a genuine error. A truthiness check would pass
//      for `{}` — hence `assert.strictEqual(result, undefined)` everywhere below.
//   2. What is retained is bounded: a digest, a byte count and the TEXT output capped at
//      `MAX_TOOL_OUTPUT_CHARS` (HOOK-06's hash-only rule, reversed by user decision so tool-output DLP
//      can fire). An image part's base64 is never retained, and neither is the tool input — both are
//      grepped for in the store's serialised snapshot.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { MAX_HASH_BYTES, MAX_TOOL_OUTPUT_CHARS, OUTPUT_TRUNCATION_MARKER } from "../../core/src/constants.ts";
import { redactSecrets } from "../../core/src/config.ts";
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

/** A store whose call `id` is recorded, as the decision seam does before any result arrives. */
function storeWithCall(id: string): ReturnType<typeof createTurnStore> {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "read", tool_use_id: id, decision: "allow" }, "sess-tr", 1);
  return store;
}

test("the result is recorded as name, isError, digest and byte count", () => {
  // The call is recorded first: since WR-03 only a recorded call's text is kept (and charged).
  const store = storeWithCall("call_read_1");
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
      // New contract: the text output rides along, capped (here whole — it fits).
      content: "file contents",
    },
  ]);
});

test("isError rides through verbatim", () => {
  const store = createTurnStore();
  recordToolResult(createFakeToolResultEvent("bash", { isError: true }), store);
  assert.equal(store.snapshot().results[0]?.is_error, true);
});

test("text output is recorded; image data and the tool input never are (T-09-10, updated)", () => {
  // Updated deliberately: this used to assert the marker was nowhere in the record. Text output is
  // now captured (capped) by user decision; what still never enters the record is an image part's
  // base64 and `event.input`.
  const IMAGE_SECRET = "IMAGE-ONLY-SECRET";
  const store = storeWithCall("call_t0910");
  const event = createFakeToolResultEvent("bash", {
    toolCallId: "call_t0910",
    input: { command: `echo ${MARKER}` },
    content: [
      { type: "text", text: `stdout:\n${MARKER}\n`, textSignature: "sig" },
      { type: "image", data: Buffer.from(IMAGE_SECRET).toString("base64"), mimeType: "image/png" },
    ],
  });

  recordToolResult(event, store);

  const serialised = JSON.stringify(store.snapshot());
  assert.equal(store.snapshot().results[0]?.content, `stdout:\n${MARKER}\n`, "the text output is held");
  assert.equal(serialised.includes(IMAGE_SECRET), false, "no decoded image content");
  assert.equal(serialised.includes(Buffer.from(IMAGE_SECRET).toString("base64")), false, "no image base64");
  assert.equal(serialised.includes("echo "), false, "and the tool input is not recorded either");
  assert.equal(serialised.includes("sig"), false, "nor provider metadata");
  assert.equal(typeof store.snapshot().results[0]?.content_sha256, "string");
});

test("a 10 MB text output is recorded capped at both ends, and the handler still returns undefined", () => {
  const store = storeWithCall("call_huge");
  const huge = "A".repeat(5_000_000) + "B".repeat(5_000_000);
  const result = recordToolResult(
    createFakeToolResultEvent("read", { toolCallId: "call_huge", content: [{ type: "text", text: huge }] }),
    store,
  );
  assert.strictEqual(result, undefined);

  const [only] = store.snapshot().results;
  assert.ok(only?.content !== undefined);
  assert.ok(only.content.length <= MAX_TOOL_OUTPUT_CHARS + OUTPUT_TRUNCATION_MARKER.length);
  assert.ok(only.content.startsWith("AAAA") && only.content.endsWith("BBBB"), "both ends kept");
  assert.equal(only.content_truncated, true);
  assert.equal(only.content_original_chars, huge.length);
  assert.equal(only.hash_skipped, true, "and the hash bail-out still applies independently");
});

test("a throwing content getter is still a silent no-op", () => {
  const store = createTurnStore();
  const event = {
    toolCallId: "c",
    toolName: "bash",
    isError: false,
    get content(): unknown[] {
      throw new Error("content getter exploded");
    },
  };
  let result: unknown = "unset";
  assert.doesNotThrow(() => {
    result = recordToolResult(event, store);
  });
  assert.strictEqual(result, undefined);
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

test("PR #371: a session key straddling the head cut is redacted before the cut (real redactSecrets)", () => {
  const key = "unb_live_" + "f00dfacecafe1234";
  const store = storeWithCall("call_straddle");
  const text = "x".repeat(MAX_TOOL_OUTPUT_CHARS / 2 - 6) + key + "y".repeat(40_000);
  recordToolResult(
    createFakeToolResultEvent("bash", { toolCallId: "call_straddle", content: [{ type: "text", text }] }),
    store,
    (t) => redactSecrets(t, key),
  );
  const [only] = store.snapshot().results;
  assert.equal(only?.content_truncated, true);
  for (let i = 0; i + 6 <= key.length; i += 1) {
    assert.equal(only?.content?.includes(key.slice(i, i + 6)), false, `fragment ${key.slice(i, i + 6)}`);
  }
  // Hash and byte count describe the ORIGINAL output, not the redacted text.
  assert.equal(only?.content_bytes, Buffer.byteLength(`text:${text}`, "utf8"));
});
