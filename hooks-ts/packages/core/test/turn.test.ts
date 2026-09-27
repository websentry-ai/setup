// HOOK-06 — the in-memory turn record and the content hash.
//
// The security-relevant assertion in this file is the negative one: a distinctive marker written
// into a tool result must not be findable anywhere in `snapshot()`. Everything else — stability,
// `textSignature` independence, the size bail-out — protects the hash's usefulness; that one
// protects the requirement.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { MAX_HASH_BYTES } from "../src/constants.ts";
import { createTurnStore, hashContent } from "../src/turn.ts";

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

  assert.deepEqual(store.snapshot().tool_calls, [
    { tool_name: "bash", tool_use_id: "call_1", decision: "deny", ts: 100 },
    { tool_name: "read", tool_use_id: "call_2", decision: "skipped", ts: 200 },
  ]);
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

test("the raw tool output is nowhere in the record (T-09-10)", () => {
  const store = createTurnStore();
  store.recordPrompt("read the credentials file", SESSION, 1);
  store.recordToolCall({ tool_name: "read", tool_use_id: "call_1", decision: "allow" }, SESSION, 2);
  const hashed = hashContent([
    { type: "text", text: `line one\n${MARKER}\nline three` },
    { type: "image", data: Buffer.from(MARKER).toString("base64"), mimeType: "image/png" },
  ]);
  store.recordResult({
    tool_name: "read",
    tool_use_id: "call_1",
    is_error: false,
    content_sha256: hashed.content_sha256,
    content_bytes: hashed.content_bytes,
  });

  const serialised = JSON.stringify(store.snapshot());
  assert.equal(serialised.includes(MARKER), false, `the marker survived into ${serialised}`);
  assert.equal(
    serialised.includes(Buffer.from(MARKER).toString("base64")),
    false,
    "and neither did its base64 encoding",
  );
  // What IS there: the digest and a count. Nothing a reader could invert.
  assert.ok(serialised.includes(String(hashed.content_sha256)), "the digest is what survives");
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
