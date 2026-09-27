// RES-04 — the `/v1/hooks/pi` body builder, and the empty-turn guard.
//
// Two of these assertions are the requirement rather than a detail of it:
//
//   * `model === "auto"`. `add_gateway_metrics_task.py:565-577` returns early on `"Model Not found"`
//     and hook telemetry never takes the `add_new_model` path, so a real model id means **no row at
//     all**. The test passes a real id in and asserts `"auto"` comes out.
//   * nothing in `tool_use[]` carries content. `tool_input` is `{}` and `tool_response` holds a
//     digest and a byte count — the serialised body is grepped for both a marker and the key names
//     that would mean file bodies had come back.

import assert from "node:assert/strict";
import test from "node:test";

import { TURNLOG_MODEL } from "../src/constants.ts";
import { buildTurnLogBody, shouldPostTurn } from "../src/turnLog.ts";
import type { TurnRecord } from "../src/turn.ts";

const MARKER = "GITHUB_TOKEN=ghp-never-on-the-wire";
const CWD = "/tmp/project";
const STARTED_AT = 1_700_000_000_000;
const COMPLETED_AT = STARTED_AT + 4_200;

function record(overrides: Partial<TurnRecord> = {}): TurnRecord {
  return {
    prompt: "read the config and summarise it",
    session_id: "sess-turnlog-1",
    started_at: STARTED_AT,
    tool_calls: [{ tool_name: "read", tool_use_id: "call_1", decision: "allow", ts: STARTED_AT + 5 }],
    results: [
      {
        tool_name: "read",
        tool_use_id: "call_1",
        is_error: false,
        content_sha256: "a".repeat(64),
        content_bytes: 812,
      },
    ],
    ...overrides,
  };
}

const build = (rec: TurnRecord) => buildTurnLogBody(rec, { cwd: CWD, completedAtMs: COMPLETED_AT });

// --- the locked model ---------------------------------------------------------------------------

test("model is the pinned constant, never a real model id", () => {
  const body = build(record());
  assert.equal(body.model, "auto");
  assert.equal(body.model, TURNLOG_MODEL, "read from the constant, not retyped at the call site");
});

// --- the two-message shape ----------------------------------------------------------------------

test("the body is two messages: the user prompt, then an assistant message carrying tool_use", () => {
  const body = build(record());

  assert.equal(body.messages.length, 2);
  assert.equal(body.messages[0]?.role, "user");
  assert.equal(body.messages[0]?.content, "read the config and summarise it");
  assert.equal(body.messages[1]?.role, "assistant");
  assert.equal(body.messages[1]?.content, "", "no assistant text is recorded, so none is invented");
  assert.equal(body.messages[1]?.tool_use?.length, 1);
});

test("each tool_use entry is the PostToolUse shape the backend reads", () => {
  const [entry] = build(record()).messages[1]?.tool_use ?? [];

  assert.equal(entry?.type, "PostToolUse");
  assert.equal(entry?.tool_name, "read");
  assert.equal(entry?.tool_use_id, "call_1");
  assert.deepEqual(entry?.tool_input, {}, "the turn record stores no tool input, by design");
  assert.deepEqual(entry?.tool_response, { content_sha256: "a".repeat(64), content_bytes: 812 });
});

test("a skipped hash is encoded honestly rather than as a missing digest", () => {
  const rec = record({
    results: [
      { tool_name: "bash", tool_use_id: "call_1", is_error: true, content_bytes: 9_000_000, hash_skipped: true },
    ],
  });
  const [entry] = build(rec).messages[1]?.tool_use ?? [];

  assert.deepEqual(entry?.tool_response, { hash_skipped: true, content_bytes: 9_000_000 });
});

test("a tool call with no matching result still appears, with an empty response", () => {
  // A denied call never ran, so there is no result to hash — but the call is the audit fact.
  const rec = record({
    tool_calls: [{ tool_name: "bash", tool_use_id: "call_denied", decision: "deny", ts: STARTED_AT }],
    results: [],
  });
  const [entry] = build(rec).messages[1]?.tool_use ?? [];

  assert.equal(entry?.tool_name, "bash");
  assert.equal(entry?.tool_use_id, "call_denied");
  assert.deepEqual(entry?.tool_response, {});
});

test("results are matched to calls by tool_use_id, not by position", () => {
  const rec = record({
    tool_calls: [
      { tool_name: "bash", tool_use_id: "c1", decision: "allow", ts: 1 },
      { tool_name: "read", tool_use_id: "c2", decision: "allow", ts: 2 },
    ],
    results: [
      { tool_name: "read", tool_use_id: "c2", is_error: false, content_sha256: "b".repeat(64), content_bytes: 10 },
      { tool_name: "bash", tool_use_id: "c1", is_error: true, content_sha256: "c".repeat(64), content_bytes: 20 },
    ],
  });
  const entries = build(rec).messages[1]?.tool_use ?? [];

  assert.equal(entries[0]?.tool_use_id, "c1");
  assert.deepEqual(entries[0]?.tool_response, { content_sha256: "c".repeat(64), content_bytes: 20 });
  assert.equal(entries[1]?.tool_use_id, "c2");
  assert.deepEqual(entries[1]?.tool_response, { content_sha256: "b".repeat(64), content_bytes: 10 });
});

// --- the rest of the body -----------------------------------------------------------------------

test("conversation_id, cwd, timestamps and a usage stub are present", () => {
  const body = build(record());

  assert.equal(body.conversation_id, "sess-turnlog-1", "it becomes thread_id and drives dedup (§B2)");
  assert.equal(body.cwd, CWD);
  assert.equal(body.requestInitialized, new Date(STARTED_AT).toISOString());
  assert.equal(body.requestCompleted, new Date(COMPLETED_AT).toISOString());
  assert.deepEqual(body.usage, { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
});

test("a record with no prompt sends an empty user message rather than omitting it", () => {
  // `messages[-1].role === 'assistant'` and a `role:'user'` entry are both read server-side
  // (`hooksHandlerFactory.ts:184-203`); dropping one would lose the other's position.
  const body = build(record({ prompt: undefined }));
  assert.equal(body.messages.length, 2);
  assert.equal(body.messages[0]?.content, "");
});

test("a record with no start time omits requestInitialized instead of guessing one", () => {
  const body = build(record({ started_at: undefined }));
  assert.equal(body.requestInitialized, undefined);
  assert.equal(body.requestCompleted, new Date(COMPLETED_AT).toISOString());
});

test("the server-set fields are never sent", () => {
  const serialised = JSON.stringify(build(record()));
  for (const forbidden of ["applicationId", "organizationId", "key_source", "unbound_app_label"]) {
    assert.equal(serialised.includes(forbidden), false, `${forbidden} is server-set (§B2)`);
  }
});

test("no raw output and no file-body key reaches the body (T-09-10)", () => {
  const rec = record({
    prompt: `please read the file containing ${MARKER}`,
    results: [
      { tool_name: "read", tool_use_id: "call_1", is_error: false, content_sha256: "d".repeat(64), content_bytes: 4 },
    ],
  });
  const body = build(rec);
  const toolUse = JSON.stringify(body.messages[1]?.tool_use);

  // The prompt IS sent — that is the existing product contract. The tool output is not.
  assert.equal(toolUse.includes(MARKER), false, `output-bearing text in ${toolUse}`);
  // Matched as quoted JSON keys, so `content_sha256` (which is meant to be there) cannot satisfy
  // the assertion for `content` (which must not be).
  for (const key of ["content", "edits", "pattern", "path", "command"]) {
    assert.equal(
      toolUse.includes(`"${key}":`),
      false,
      `tool_use[] carries a ${key} key: ${toolUse}`,
    );
  }
  assert.ok(toolUse.includes('"content_sha256":'), "the digest, by contrast, is present");
});

// --- the empty-turn guard (mirrors PY:4975 `if len(messages) < 2`) -------------------------------

test("shouldPostTurn refuses a turn with neither a prompt nor a tool call", () => {
  assert.equal(shouldPostTurn({ tool_calls: [], results: [] }), false);
  assert.equal(
    shouldPostTurn({ tool_calls: [], results: [{ tool_name: "bash", tool_use_id: "c", is_error: false, content_bytes: 1 }] }),
    false,
    "a result with no call belongs to a turn already posted",
  );
  assert.equal(shouldPostTurn(undefined), false);
});

test("shouldPostTurn accepts a prompt-only turn and a tool-call-only turn", () => {
  assert.equal(shouldPostTurn({ prompt: "hello", tool_calls: [], results: [] }), true);
  assert.equal(
    shouldPostTurn({ tool_calls: [{ tool_name: "bash", tool_use_id: "c", decision: "allow", ts: 1 }], results: [] }),
    true,
    "an extension-initiated run has no prompt and is still a real turn (§F3)",
  );
});

test("the builder never throws on a malformed record", () => {
  assert.doesNotThrow(() => buildTurnLogBody(undefined as never, { cwd: CWD, completedAtMs: COMPLETED_AT }));
  assert.doesNotThrow(() =>
    buildTurnLogBody({ tool_calls: undefined, results: undefined } as never, {
      cwd: CWD,
      completedAtMs: COMPLETED_AT,
    }),
  );
});
