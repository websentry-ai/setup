// HOOK-06 — the in-memory turn record, the content hash and the captured output text.
//
// The security-relevant assertions in this file are about what the record may hold. HOOK-06 used to
// be hash-only, proved by grepping `snapshot()` for a marker; that rule was reversed by user decision
// (tool output is sent, capped and redacted), so the marker test is INVERTED deliberately: a marker in
// a TEXT part now does appear, within the cap, while a marker hidden in an IMAGE part's base64 still
// never does. The caps (per result and per turn) are asserted directly. Everything else — stability,
// `textSignature` independence, the size bail-out — protects the hash's usefulness.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  MAX_HASH_BYTES,
  MAX_TOOL_OUTPUT_CHARS,
  MAX_TURN_OUTPUT_CHARS,
  MAX_TURN_RESULTS,
  MAX_TURN_TOOL_CALLS,
  OUTPUT_TRUNCATION_MARKER,
} from "../src/constants.ts";
import { captureText, createTurnStore, hashContent } from "../src/turn.ts";
import type { TurnResult } from "../src/turn.ts";

const SESSION = "sess-turn-1";
/** Nothing else in the suite contains this string, so a grep for it is decisive. */
const MARKER = "AWS_SECRET_ACCESS_KEY=NEVER-LEAVES-THE-PROCESS";

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

// --- hashContent -------------------------------------------------------------------------------

test("hashContent is stable across calls and sensitive to the text", () => {
  const first = hashContent([{ type: "text", text: "abc" }]);
  const second = hashContent([{ type: "text", text: "abc" }]);
  const other = hashContent([{ type: "text", text: "abd" }]);

  assert.equal(first.content_sha256, second.content_sha256, "same input, same digest");
  assert.notEqual(first.content_sha256, other.content_sha256, "one character changes the digest");
  assert.equal(first.hash_skipped, undefined, "a three-byte projection is not skipped");
  // The digest is over the canonical projection, not over the object.
  assert.equal(first.content_sha256, sha256("text:abc"));
  assert.equal(first.content_bytes, Buffer.byteLength("text:abc", "utf8"));
});

test("provider metadata and key order do not change the hash", () => {
  const plain = hashContent([{ type: "text", text: "same" }]);
  const signed = hashContent([{ type: "text", text: "same", textSignature: "sig-from-provider" }]);
  // Key order differs from both of the above; `JSON.stringify` would not agree with itself here.
  const reordered = hashContent([{ text: "same", type: "text" }]);

  assert.equal(signed.content_sha256, plain.content_sha256, "textSignature is provider metadata");
  assert.equal(reordered.content_sha256, plain.content_sha256, "key order is not content");
  assert.equal(signed.content_bytes, plain.content_bytes);
});

test("an image part contributes its mime type and its base64 data, counted as encoded bytes", () => {
  const data = Buffer.from("binary-ish payload").toString("base64");
  const projection = `image:image/png:${data}`;
  const hashed = hashContent([{ type: "image", data, mimeType: "image/png" }]);

  assert.equal(hashed.content_sha256, sha256(projection));
  assert.equal(hashed.content_bytes, Buffer.byteLength(projection, "utf8"));
  assert.ok(
    hashed.content_bytes > Buffer.byteLength("binary-ish payload", "utf8"),
    "the count is the base64 (encoded) length, never the decoded size",
  );
});

test("multiple parts are joined with a newline, in order", () => {
  const forwards = hashContent([
    { type: "text", text: "one" },
    { type: "text", text: "two" },
  ]);
  const backwards = hashContent([
    { type: "text", text: "two" },
    { type: "text", text: "one" },
  ]);

  assert.equal(forwards.content_sha256, sha256("text:one\ntext:two"));
  assert.notEqual(forwards.content_sha256, backwards.content_sha256, "order is content");
});

test("an empty content array hashes the empty projection and counts zero bytes", () => {
  const hashed = hashContent([]);
  assert.equal(hashed.content_bytes, 0);
  assert.equal(hashed.content_sha256, sha256(""));
  assert.equal(hashed.hash_skipped, undefined);
});

test("a malformed part is projected defensively rather than throwing", () => {
  // `content` comes off a third-party tool at runtime: it can genuinely be junk.
  assert.doesNotThrow(() => hashContent([null, undefined, 42, { type: "text" }] as unknown[]));
  const hashed = hashContent([null] as unknown[]);
  assert.equal(typeof hashed.content_sha256, "string");
});

test("content above MAX_HASH_BYTES is counted but never hashed", () => {
  // The projection prefix pushes this over the cap on its own; +1 makes the intent explicit.
  const big = "x".repeat(MAX_HASH_BYTES + 1);
  const hashed = hashContent([{ type: "text", text: big }]);

  assert.equal(hashed.hash_skipped, true);
  assert.equal(hashed.content_sha256, undefined, "a skipped hash must not report a digest");
  assert.equal(hashed.content_bytes, Buffer.byteLength(`text:${big}`, "utf8"));
});

test("content just under the cap is still hashed", () => {
  const text = "y".repeat(MAX_HASH_BYTES - "text:".length);
  const hashed = hashContent([{ type: "text", text }]);
  assert.equal(hashed.hash_skipped, undefined);
  assert.equal(typeof hashed.content_sha256, "string");
  assert.equal(hashed.content_bytes, MAX_HASH_BYTES);
});

// --- the store ---------------------------------------------------------------------------------

test("an untouched store is empty and takes nothing", () => {
  const store = createTurnStore();
  assert.equal(store.isEmpty(), true);
  assert.equal(store.take(), undefined, "an empty turn is never posted");
  assert.deepEqual(store.snapshot().tool_calls, []);
  assert.deepEqual(store.snapshot().results, []);
});

test("recordPrompt lazily starts the turn and stamps the session", () => {
  const store = createTurnStore();
  store.recordPrompt("what is in /etc/passwd?", SESSION, 1_000);

  const snap = store.snapshot();
  assert.equal(snap.prompt, "what is in /etc/passwd?");
  assert.equal(snap.session_id, SESSION);
  assert.equal(snap.started_at, 1_000);
  assert.equal(store.isEmpty(), false);
});

test("a turn that begins with a tool call still carries a session id and a start time", () => {
  // An extension-initiated run: `agent_end` fires for it too, and there was no `input` event.
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 500);

  const snap = store.snapshot();
  assert.equal(snap.session_id, SESSION, "conversation_id is load-bearing — it becomes thread_id");
  assert.equal(snap.started_at, 500);
  assert.equal(snap.prompt, undefined, "and there is no prompt to invent");
  assert.equal(store.isEmpty(), false, "a tool call alone is a postable turn");
});

test("a later event in the SAME session never resets started_at or session_id", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 500);
  store.recordPrompt("late prompt", SESSION, 9_000);
  store.recordToolCall({ tool_name: "read", tool_use_id: "call_2", decision: "skipped" }, SESSION, 9_500);

  const snap = store.snapshot();
  assert.equal(snap.started_at, 500, "the turn started when its first event arrived");
  assert.equal(snap.session_id, SESSION);
  assert.equal(snap.prompt, "late prompt");
  assert.equal(snap.tool_calls.length, 2);
});

test("a DIFFERENT session id rolls the record over instead of joining it", () => {
  // `/new` mid-turn. The old record can never be posted under the new `conversation_id` — that value
  // becomes `thread_id` server-side, so joining them would stitch two conversations into one thread.
  const store = createTurnStore();
  store.recordPrompt("old question", SESSION, 500);
  store.recordResult({ tool_name: "bash", tool_use_id: "call_1", is_error: false, content_bytes: 3 });
  store.recordToolCall({ tool_name: "user_bash", tool_use_id: "ubash_1", decision: "allow" }, "sess-new", 9_000);

  const snap = store.snapshot();
  assert.equal(snap.session_id, "sess-new", "the new session owns the record");
  assert.equal(snap.started_at, 9_000, "and it started when its own first event arrived");
  assert.equal(snap.prompt, undefined, "the old prompt went with the old session");
  assert.deepEqual(
    snap.tool_calls.map((call) => call.tool_use_id),
    ["ubash_1"],
    "and so did the old calls",
  );
  assert.deepEqual(snap.results, [], "and the old results");
});

test("an unknown session id neither stamps nor rolls over", () => {
  // `sessionIdOf` answers `""` for a ctx it cannot read. That is "not known", not "changed": it must
  // never be able to discard a turn that is mid-flight.
  const store = createTurnStore();
  store.recordPrompt("still going", SESSION, 500);
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, "", 9_000);

  const snap = store.snapshot();
  assert.equal(snap.session_id, SESSION);
  assert.equal(snap.started_at, 500);
  assert.equal(snap.prompt, "still going", "the live record survives an unreadable id");
  assert.equal(snap.tool_calls.length, 1, "and the call is still recorded");
});

test("reset drops a record from another session and keeps one from this session", () => {
  const store = createTurnStore();
  store.recordPrompt("old question", SESSION, 500);

  // Same session arriving again — `/reload` re-fires `session_start` with it. Nothing to drop.
  store.reset(SESSION);
  assert.equal(store.snapshot().prompt, "old question", "the same session keeps its turn");

  // An id that cannot be read is not evidence of a change either.
  store.reset("");
  assert.equal(store.snapshot().prompt, "old question", "an unknown id drops nothing");

  // A different session: the pending record is dropped outright, never posted. `agent_end` never
  // fired for it, so nothing says that turn finished.
  store.reset("sess-new");
  assert.deepEqual(store.snapshot(), { tool_calls: [], results: [] });
  assert.equal(store.isEmpty(), true);
  assert.equal(store.take(), undefined, "there is nothing left to post");
});

test("tool calls keep their decision and a timestamp, in arrival order", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "deny" }, SESSION, 100);
  store.recordToolCall({ tool_name: "read", tool_use_id: "call_2", decision: "skipped" }, SESSION, 200);

  // `session_id` is part of the stored shape since WR-04 — stamped at record time so a pending
  // `!cmd` call can be attributed rather than merely dropped. It is never sent (see turnLog.test.ts).
  assert.deepEqual(store.snapshot().tool_calls, [
    { tool_name: "bash", tool_use_id: "call_1", decision: "deny", ts: 100, session_id: SESSION },
    { tool_name: "read", tool_use_id: "call_2", decision: "skipped", ts: 200, session_id: SESSION },
  ]);
});

test("a tool call carries the allowlisted input it was checked with", () => {
  // The turn log's `tool_input` has no other source: `agent_end` cannot see `event.input`, and
  // reaching back for it would re-open the egress the allowlist closed. What the decision seam hands
  // over is the already-sanitised projection, so the record stores it as-is.
  const store = createTurnStore();
  store.recordToolCall(
    { tool_name: "bash", tool_use_id: "call_1", decision: "allow", tool_input: { command: "echo hi" } },
    SESSION,
    100,
  );
  assert.deepEqual(store.snapshot().tool_calls[0]?.tool_input, { command: "echo hi" });

  // Absent stays absent — a call recorded without one must not grow an empty object on the wire.
  const bare = createTurnStore();
  bare.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 100);
  assert.equal(bare.snapshot().tool_calls[0]?.tool_input, undefined);

  // And a non-object is not stored at all, rather than stored as junk.
  const junk = createTurnStore();
  junk.recordToolCall(
    {
      tool_name: "bash",
      tool_use_id: "call_1",
      decision: "allow",
      tool_input: "command" as unknown as Record<string, unknown>,
    },
    SESSION,
    100,
  );
  assert.equal(junk.snapshot().tool_calls[0]?.tool_input, undefined);
});

test("a stored tool_input cannot be mutated through the caller's object or through a snapshot", () => {
  const store = createTurnStore();
  const live: Record<string, unknown> = { command: "echo hi" };
  store.recordToolCall(
    { tool_name: "bash", tool_use_id: "call_1", decision: "allow", tool_input: live },
    SESSION,
    100,
  );

  live.command = "rm -rf /";
  live.content = "a file body";
  assert.deepEqual(
    store.snapshot().tool_calls[0]?.tool_input,
    { command: "echo hi" },
    "the record copied it, so a later mutation of the caller's object cannot reach the wire",
  );

  const snap = store.snapshot();
  (snap.tool_calls[0]?.tool_input as Record<string, unknown>).command = "injected";
  assert.deepEqual(store.snapshot().tool_calls[0]?.tool_input, { command: "echo hi" });
});

test("recordResult stores a name, a flag, a digest and a count — and no text", () => {
  const store = createTurnStore();
  const hashed = hashContent([{ type: "text", text: MARKER }]);
  store.recordResult({
    tool_name: "bash",
    tool_use_id: "call_1",
    is_error: false,
    content_sha256: hashed.content_sha256,
    content_bytes: hashed.content_bytes,
  });

  assert.deepEqual(store.snapshot().results, [
    {
      tool_name: "bash",
      tool_use_id: "call_1",
      is_error: false,
      content_sha256: sha256(`text:${MARKER}`),
      content_bytes: Buffer.byteLength(`text:${MARKER}`, "utf8"),
    },
  ]);
});

test("text output is held within the cap; image data never is (T-09-10, inverted for text)", () => {
  // Deliberately inverted: this used to assert the marker was NOWHERE in the record. Tool output is
  // now captured by user decision, so a TEXT marker is expected in `snapshot()` — and the half of
  // T-09-10 that still holds is asserted next to it: an image part's base64 (which also carries the
  // marker, encoded) never enters the record at all.
  const store = createTurnStore();
  store.recordPrompt("read the credentials file", SESSION, 1);
  store.recordToolCall({ tool_name: "read", tool_use_id: "call_1", decision: "allow" }, SESSION, 2);
  const IMAGE_ONLY = "IMAGE-ONLY-" + MARKER;
  const parts = [
    { type: "text", text: `line one\n${MARKER}\nline three` },
    { type: "image", data: Buffer.from(IMAGE_ONLY).toString("base64"), mimeType: "image/png" },
  ];
  const hashed = hashContent(parts);
  const captured = captureText(parts, MAX_TOOL_OUTPUT_CHARS);
  store.recordResult({
    tool_name: "read",
    tool_use_id: "call_1",
    is_error: false,
    content_sha256: hashed.content_sha256,
    content_bytes: hashed.content_bytes,
    ...(captured === undefined ? {} : { content: captured.text }),
  });

  const serialised = JSON.stringify(store.snapshot());
  assert.ok(serialised.includes(MARKER), "the text output is held");
  assert.equal(store.snapshot().results[0]?.content, `line one\n${MARKER}\nline three`);
  assert.equal(serialised.includes(IMAGE_ONLY), false, "no decoded image content");
  assert.equal(
    serialised.includes(Buffer.from(IMAGE_ONLY).toString("base64")),
    false,
    "and no image base64 — images are hash and bytes only",
  );
  assert.ok(serialised.includes(String(hashed.content_sha256)), "the digest is still there");
});

test("a skipped hash is recorded as such rather than as a digest", () => {
  const store = createTurnStore();
  store.recordResult({
    tool_name: "bash",
    tool_use_id: "call_1",
    is_error: true,
    content_bytes: MAX_HASH_BYTES + 1,
    hash_skipped: true,
  });

  const [only] = store.snapshot().results;
  assert.equal(only?.hash_skipped, true);
  assert.equal(only?.content_sha256, undefined);
  assert.equal(only?.is_error, true);
  assert.equal(only?.content_bytes, MAX_HASH_BYTES + 1);
});

test("a result alone does not make a turn postable", () => {
  // Mirrors PY:4975 — no prompt and no tool call is noise, whatever else arrived.
  const store = createTurnStore();
  store.recordResult({ tool_name: "bash", tool_use_id: "call_1", is_error: false, content_bytes: 2 });
  assert.equal(store.isEmpty(), true);
});

test("take returns the record once and leaves the store empty", () => {
  const store = createTurnStore();
  store.recordPrompt("first turn", SESSION, 10);
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 11);

  const taken = store.take();
  assert.equal(taken?.prompt, "first turn");
  assert.equal(taken?.tool_calls.length, 1);

  // A retry `agent_end` in the same prompt must find nothing to re-post (§F3).
  assert.equal(store.isEmpty(), true);
  assert.equal(store.take(), undefined);

  // And the taken record is a detached copy: emptying the store did not hollow it out.
  assert.equal(taken?.tool_calls[0]?.tool_use_id, "call_1");
});

test("the results array is capped, dropping the oldest and counting the drops", () => {
  // The backstop for an unbounded turn. `tool_result` fires once per tool result with no ceiling on
  // how many a single turn can produce, and the record lives for the whole turn — so without a cap
  // the array is the one part of this module that can grow without limit.
  const store = createTurnStore();
  const result = (index: number): TurnResult => ({
    tool_name: "bash",
    tool_use_id: `call_${index}`,
    is_error: false,
    content_bytes: 1,
  });

  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_0", decision: "allow" }, SESSION, 100);
  const overflow = 100;
  for (let i = 0; i < MAX_TURN_RESULTS + overflow; i += 1) store.recordResult(result(i));

  const snap = store.snapshot();
  assert.equal(MAX_TURN_RESULTS, 500, "the cap is stated here so a change to it is deliberate");
  assert.equal(snap.results.length, MAX_TURN_RESULTS, "never more than the cap is retained");
  assert.equal(snap.results_truncated, overflow, "and the drops are counted, not hidden");
  // Drop-OLDEST: the most recent results are the ones a developer is looking at, and the earliest
  // calls keep an honest empty `tool_response` rather than a wrong digest.
  assert.equal(snap.results[0]?.tool_use_id, `call_${overflow}`, "the oldest went first");
  assert.equal(snap.results.at(-1)?.tool_use_id, `call_${MAX_TURN_RESULTS + overflow - 1}`);

  // The counter belongs to the turn, so the next one starts clean.
  assert.equal(store.take()?.results_truncated, overflow);
  assert.equal(store.snapshot().results_truncated, undefined, "a fresh turn has nothing truncated");
});

test("a turn under the cap reports no truncation at all", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_0", decision: "allow" }, SESSION, 100);
  store.recordResult({ tool_name: "bash", tool_use_id: "call_0", is_error: false, content_bytes: 1 });
  assert.equal(store.snapshot().results_truncated, undefined, "absent, never a zero to explain");
});

test("take always empties the store, even when there is nothing to post", () => {
  // The orphan-result case. A turn can record results without ever *starting*: a custom or MCP tool
  // takes the nothing-evaluable skip and records no decision, and an extension-sourced prompt records
  // no prompt — so `started()` stays false while `tool_result` keeps arriving. `take()` used to return
  // `undefined` WITHOUT resetting, so those results sat here until some later turn started, which
  // meant `agent_end` had no way to drain them at all.
  const store = createTurnStore();
  store.recordResult({ tool_name: "mcp__db__query", tool_use_id: "call_1", is_error: false, content_bytes: 9 });
  store.recordResult({ tool_name: "mcp__db__query", tool_use_id: "call_2", is_error: false, content_bytes: 9 });
  assert.equal(store.snapshot().results.length, 2);

  assert.equal(store.take(), undefined, "still not postable — a result alone is not a turn");
  assert.deepEqual(
    store.snapshot(),
    { tool_calls: [], results: [] },
    "but consumed and dropped, so the next turn starts clean",
  );
});

test("snapshot is a copy — a caller cannot mutate the live record", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 1);
  const snap = store.snapshot();
  snap.tool_calls.push({ tool_name: "injected", tool_use_id: "x", decision: "allow", ts: 0 });
  snap.prompt = "injected";

  assert.equal(store.snapshot().tool_calls.length, 1);
  assert.equal(store.snapshot().prompt, undefined);
});

test("the store never throws, whatever it is handed", () => {
  const store = createTurnStore();
  assert.doesNotThrow(() => {
    store.recordPrompt(undefined as unknown as string, SESSION, 1);
    store.recordToolCall(undefined as unknown as { tool_name: string; tool_use_id: string; decision: string }, SESSION, 2);
    store.recordResult(undefined as unknown as { tool_name: string; tool_use_id: string; is_error: boolean; content_bytes: number });
    store.snapshot();
    store.take();
  }, "a store fault must never reach a handler — pi reads a throw as a block");
});

// --- WR-03: the cap must fire before the projection is built, not after -------------------------

test("WR-03 an oversize result is sized without allocating a copy of itself", () => {
  // 20 MB, five times the cap. `list.map(projectPart)` used to run before the count could fire, on
  // the AWAITED pass between a tool finishing and the model seeing its output.
  const big = "x".repeat(20 * 1024 * 1024);
  assert.ok(big.length > MAX_HASH_BYTES * 4, "the fixture must be well past the cap");

  // Pre-warm, and this is the subtle part of the measurement. `"text:" + big` allocates almost
  // nothing on its own — V8 returns a lazy cons string — so the old code's copy was not the `+`, it
  // was the `Buffer.byteLength` that had to FLATTEN that cons string to measure it. Measuring `big`
  // itself once here pays V8's one-time flatten for the fixture, so the delta below cannot be
  // attributed to anything but work `hashContent` does on top of it. Measured both ways at this
  // fixture size: old shape 20.9 MB, new shape 240 bytes.
  Buffer.byteLength(big, "utf8");

  const before = process.memoryUsage().heapUsed;
  const hashed = hashContent([{ type: "text", text: big }]);
  const delta = process.memoryUsage().heapUsed - before;

  assert.equal(hashed.hash_skipped, true);
  assert.equal(hashed.content_sha256, undefined);
  // The count is still exact, not "however far we got": sizing is a scan, so bailing early would
  // save nothing and would make `content_bytes` a lower bound on the one path where it is the only
  // thing reported.
  assert.equal(hashed.content_bytes, Buffer.byteLength(`text:${big}`, "utf8"));
  // 1 MB is ~4000× the new shape's allocation and ~1/20th of the old shape's, so heap-accounting
  // noise cannot move this either way.
  assert.ok(
    delta < 1024 * 1024,
    `sizing a ${big.length}-byte part allocated ${delta} bytes; the projection is being built`,
  );
});

test("WR-03 feeding the digest in two updates did not change any digest", () => {
  // The byte stream is prefix-then-body per part, `\n` between parts — identical to the joined
  // projection it replaced. Pinned against literal `createHash` calls so a future refactor of
  // `projectPart` cannot quietly re-key every stored hash.
  const text = createHash("sha256").update("text:abc", "utf8").digest("hex");
  assert.equal(hashContent([{ type: "text", text: "abc" }]).content_sha256, text);

  const image = createHash("sha256").update("image:image/png:AAAA", "utf8").digest("hex");
  assert.equal(
    hashContent([{ type: "image", data: "AAAA", mimeType: "image/png" }]).content_sha256,
    image,
  );

  const joined = createHash("sha256").update("text:a\ntext:b", "utf8").digest("hex");
  assert.equal(
    hashContent([{ type: "text", text: "a" }, { type: "text", text: "b" }]).content_sha256,
    joined,
  );
});

// --- WR-04: tool_calls is bounded, and attributed to the session it happened in -----------------

test("WR-04 tool_calls is capped drop-oldest with a counter, exactly like results", () => {
  // The clearer unbounded path of the two, and not hypothetical: `user_bash` records a call and pi
  // fires no `agent_end` for a bare `!cmd`, so nothing calls `take()` and the entry lives for the
  // whole session. A developer working through a series of them accumulated one per invocation.
  const store = createTurnStore();
  const overflow = 100;
  for (let i = 0; i < MAX_TURN_TOOL_CALLS + overflow; i += 1) {
    store.recordToolCall({ tool_name: "bash", tool_use_id: `call_${i}`, decision: "allow" }, SESSION, 100 + i);
  }

  const snap = store.snapshot();
  assert.equal(MAX_TURN_TOOL_CALLS, 500, "the cap is stated here so a change to it is deliberate");
  assert.equal(snap.tool_calls.length, MAX_TURN_TOOL_CALLS, "never more than the cap is retained");
  assert.equal(snap.tool_calls_truncated, overflow, "and the drops are counted, not hidden");
  assert.equal(snap.tool_calls[0]?.tool_use_id, `call_${overflow}`, "the oldest went first");
  assert.equal(snap.tool_calls.at(-1)?.tool_use_id, `call_${MAX_TURN_TOOL_CALLS + overflow - 1}`);

  assert.equal(store.take()?.tool_calls_truncated, overflow);
  assert.equal(store.snapshot().tool_calls_truncated, undefined, "a fresh turn has nothing truncated");
});

test("WR-04 a call is stamped with the session it happened in", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, SESSION, 100);
  assert.equal(store.snapshot().tool_calls[0]?.session_id, SESSION);

  // `sessionIdOf` answers `""` for a ctx it cannot read. That means "not known", so nothing is
  // stamped — an empty string would be a claim about a session that does not exist.
  const blind = createTurnStore();
  blind.recordToolCall({ tool_name: "bash", tool_use_id: "call_1", decision: "allow" }, "", 100);
  assert.equal(blind.snapshot().tool_calls[0]?.session_id, undefined);
});

test("WR-04 a pending !cmd call from an unidentified session cannot ride the next turn's row", () => {
  // The hole the whole-record rollover cannot see. `record.session_id` is only ever set from the
  // FIRST event, so when that event carried no readable id the record has none — and a later real id
  // then never "differs" from it. Before the per-entry stamp, the earlier session's `!cmd` rode the
  // next model-driven turn's `tool_use[]`, producing a row claiming two calls for a turn that made
  // one, which is worse for an audit trail than a missing row.
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "old_cmd", decision: "allow" }, "sess-A", 100);
  // No `session_start` in between: `/resume` and `/fork` re-fire it, but nothing guarantees this
  // store sees one before the next tool call arrives.
  store.recordToolCall({ tool_name: "read", tool_use_id: "new_call", decision: "allow" }, "sess-B", 200);

  const snap = store.snapshot();
  assert.deepEqual(
    snap.tool_calls.map((entry) => entry.tool_use_id),
    ["new_call"],
    "the foreign entry is discarded, this session's work is kept",
  );
  assert.equal(snap.session_id, "sess-B");
});

test("WR-04 an unstamped entry is kept — absent means 'unknown', not 'foreign'", () => {
  const store = createTurnStore();
  store.recordToolCall({ tool_name: "bash", tool_use_id: "blind_cmd", decision: "allow" }, "", 100);
  store.recordToolCall({ tool_name: "read", tool_use_id: "known", decision: "allow" }, "sess-A", 200);

  // Dropping an entry we merely cannot attribute would lose a real call from THIS session, which is
  // the more likely reading of an unreadable ctx.
  assert.deepEqual(
    store.snapshot().tool_calls.map((entry) => entry.tool_use_id),
    ["blind_cmd", "known"],
  );
});

// --- currentPrompt (the pretool `messages` source) ----------------------------------------------
//
// The gateway writes its block/warn row from the pretool `messages`, so `tool_call` reads the turn's
// prompt through this getter on every evaluated call. It is the per-tool-call path: no copy, and
// total.

test("currentPrompt returns the pending prompt for the same session", () => {
  const store = createTurnStore();
  store.recordPrompt("what does this repo do?", SESSION, 1_000);
  assert.equal(store.currentPrompt(SESSION), "what does this repo do?");
});

test("currentPrompt is undefined with no prompt, or for a different session", () => {
  const store = createTurnStore();
  assert.equal(store.currentPrompt(SESSION), undefined, "nothing recorded yet");
  store.recordToolCall({ tool_name: "bash", tool_use_id: "c1", decision: "allow" }, SESSION, 1_000);
  assert.equal(store.currentPrompt(SESSION), undefined, "a call-only turn has no prompt");
  store.recordPrompt("mine", SESSION, 1_100);
  assert.equal(store.currentPrompt("someone-else"), undefined, "a foreign session's prompt is not ours");
});

test("currentPrompt answers for an unknown ('') session id and an unstamped record", () => {
  const store = createTurnStore();
  store.recordPrompt("stamped", SESSION, 1_000);
  assert.equal(store.currentPrompt(""), "stamped", "'' means not known, never 'changed'");

  const unstamped = createTurnStore();
  unstamped.recordPrompt("unstamped", "", 1_000);
  assert.equal(unstamped.snapshot().session_id, undefined);
  assert.equal(unstamped.currentPrompt(SESSION), "unstamped", "no stored session to disagree with");
});

test("currentPrompt is total, including after take()", () => {
  const store = createTurnStore();
  store.recordPrompt("gone soon", SESSION, 1_000);
  store.take();
  assert.equal(store.currentPrompt(SESSION), undefined);
  assert.doesNotThrow(() => store.currentPrompt(undefined as unknown as string));
  assert.doesNotThrow(() => store.currentPrompt(null as unknown as string));
});

test("currentPrompt does not go through snapshot() (no per-call copy)", () => {
  const store = createTurnStore();
  store.recordPrompt("cheap", SESSION, 1_000);
  store.snapshot = () => {
    throw new Error("currentPrompt must not deep-copy the record");
  };
  assert.equal(store.currentPrompt(SESSION), "cheap");
});

// --- captureText (the output text the turn log carries) ----------------------------------------

test("captureText returns the joined text parts whole when they fit", () => {
  const captured = captureText(
    [
      { type: "text", text: "first" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
      { type: "text", text: "second", textSignature: "sig" },
    ],
    100,
  );
  assert.deepStrictEqual(captured, { text: "first\nsecond" }, "images skipped, text joined with \\n");
});

test("captureText keeps head and tail with the marker when over the cap", () => {
  const big = "H".repeat(10_000) + "M".repeat(10_000) + "T".repeat(10_000);
  const captured = captureText([{ type: "text", text: big }], MAX_TOOL_OUTPUT_CHARS);
  assert.ok(captured !== undefined);
  assert.equal(captured.truncated, true);
  assert.equal(captured.original_chars, big.length);
  assert.equal(captured.text.length, MAX_TOOL_OUTPUT_CHARS + OUTPUT_TRUNCATION_MARKER.length);
  assert.ok(captured.text.startsWith("H".repeat(MAX_TOOL_OUTPUT_CHARS / 2)));
  assert.ok(captured.text.endsWith("T".repeat(MAX_TOOL_OUTPUT_CHARS / 2)));
  assert.equal(captured.text.includes("M"), false, "the middle is what goes");
  assert.ok(captured.text.includes(OUTPUT_TRUNCATION_MARKER));
});

test("captureText head and tail span part boundaries", () => {
  const captured = captureText(
    [
      { type: "text", text: "aaaa" },
      { type: "text", text: "bbbbbbbbbbbbbbbbbbbb" },
      { type: "text", text: "cccc" },
    ],
    12,
  );
  // Stream: "aaaa\nbbbb…bbbb\ncccc" — first 6 and last 6 characters.
  assert.equal(captured?.text, "aaaa\nb" + OUTPUT_TRUNCATION_MARKER + "b\ncccc");
  assert.equal(captured?.original_chars, 4 + 1 + 20 + 1 + 4);
});

test("captureText: an all-image result has no text; hostile parts are undefined, never a throw", () => {
  assert.equal(captureText([{ type: "image", data: "eA==", mimeType: "image/png" }], 100), undefined);
  assert.equal(captureText([], 100), undefined);
  assert.equal(captureText("nope" as unknown as unknown[], 100), undefined);
  assert.equal(captureText(null as unknown as unknown[], 100), undefined);
  const hostile = [
    new Proxy({}, { get: () => { throw new Error("getter exploded"); } }),
  ];
  assert.doesNotThrow(() => captureText(hostile, 100));
  assert.equal(captureText(hostile, 100), undefined);
});

// --- The per-turn output budget -----------------------------------------------------------------

test("once the turn's output budget is spent, results keep hash and bytes but no text", () => {
  const store = createTurnStore();
  store.recordPrompt("p", SESSION, 1);
  const chunk = "x".repeat(MAX_TOOL_OUTPUT_CHARS);
  const fits = Math.floor(MAX_TURN_OUTPUT_CHARS / MAX_TOOL_OUTPUT_CHARS);
  for (let i = 0; i < fits + 2; i += 1) {
    store.recordResult({
      tool_name: "bash",
      tool_use_id: `c${i}`,
      is_error: false,
      content_sha256: "a".repeat(64),
      content_bytes: chunk.length,
      content: chunk,
    });
  }
  const results = store.snapshot().results;
  assert.equal(results.filter((r) => r.content !== undefined).length, fits, "exactly the budget's worth");
  const over = results.slice(fits);
  for (const r of over) {
    assert.equal(r.content, undefined);
    assert.equal(r.content_omitted, true);
    assert.equal(r.content_sha256, "a".repeat(64), "the hash still describes the output");
    assert.equal(r.content_bytes, chunk.length);
  }
});

test("the output budget resets on take() and on a session rollover", () => {
  const store = createTurnStore();
  const chunk = "y".repeat(MAX_TURN_OUTPUT_CHARS);
  const fill = (id: string) =>
    store.recordResult({ tool_name: "bash", tool_use_id: id, is_error: false, content_bytes: 1, content: chunk });

  store.recordPrompt("one", SESSION, 1);
  fill("a1");
  fill("a2");
  assert.equal(store.snapshot().results[1]?.content_omitted, true, "spent");
  store.take();

  store.recordPrompt("two", SESSION, 2);
  fill("b1");
  assert.equal(store.snapshot().results[0]?.content, chunk, "a fresh turn has a fresh budget");

  store.recordPrompt("three", "another-session", 3);
  fill("c1");
  assert.equal(store.snapshot().results[0]?.content, chunk, "and so does a rolled-over record");
});
