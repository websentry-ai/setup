// RES-04 — the `/v1/hooks/pi` body builder, and the empty-turn guard.
//
// Two of these assertions are the requirement rather than a detail of it:
//
//   * `model === "auto"`. `add_gateway_metrics_task.py:565-577` returns early on `"Model Not found"`
//     and hook telemetry never takes the `add_new_model` path, so a real model id means **no row at
//     all**. The test passes a real id in and asserts `"auto"` comes out.
//   * nothing in `tool_use[]` carries content. `tool_input` carries the SAME allowlisted projection
//     the pretool request sends — `command`, `path`, `pattern` — and `tool_response` holds a digest
//     and a byte count. The serialised body is grepped for a marker and for the two key names that
//     would mean file bodies had come back (`content`, `edits`), and asserted to contain the three
//     that must be there.

import assert from "node:assert/strict";
import test from "node:test";

import { MAX_ASSISTANT_CHARS, TURNLOG_MODEL } from "../src/constants.ts";
import { COMMAND_TRUNCATION_MARKER } from "../src/payload.ts";
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
    tool_calls: [
      {
        tool_name: "read",
        tool_use_id: "call_1",
        decision: "allow",
        ts: STARTED_AT + 5,
        tool_input: { path: "/etc/app/config.yaml" },
      },
    ],
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
/** The same, with the assistant text `agent_end` extracted from its messages. */
const buildWith = (rec: TurnRecord, assistantText: string | undefined) =>
  buildTurnLogBody(rec, { cwd: CWD, completedAtMs: COMPLETED_AT, assistantText });

// --- the locked model ---------------------------------------------------------------------------

test("model is the pinned constant, never a real model id", () => {
  const body = build(record());
  assert.equal(body.model, "auto");
  assert.equal(body.model, TURNLOG_MODEL, "read from the constant, not retyped at the call site");
});

test("results_truncated rides the body only when results were actually dropped", () => {
  // A row that silently described 500 of 600 results would be worse than a short row: it would look
  // complete. The count is the one honest thing to say about what is missing.
  assert.equal(build(record()).results_truncated, undefined, "absent by default, never a zero");
  assert.equal(build(record({ results_truncated: 0 })).results_truncated, undefined, "and never a zero");
  assert.equal(build(record({ results_truncated: 100 })).results_truncated, 100);
  // Not a count the server can be made to mis-read: a nonsense value is dropped, not forwarded.
  assert.equal(build(record({ results_truncated: -4 })).results_truncated, undefined);
  assert.equal(
    build(record({ results_truncated: "lots" as unknown as number })).results_truncated,
    undefined,
  );
});

// --- the two-message shape ----------------------------------------------------------------------

test("the body is two messages: the user prompt, then an assistant message carrying tool_use", () => {
  const body = build(record());

  assert.equal(body.messages.length, 2);
  assert.equal(body.messages[0]?.role, "user");
  assert.equal(body.messages[0]?.content, "read the config and summarise it");
  assert.equal(body.messages[1]?.role, "assistant");
  assert.equal(body.messages[1]?.content, "", "no assistant text was passed, so none is invented");
  assert.equal(body.messages[1]?.tool_use?.length, 1);
});

// --- the assistant text ---------------------------------------------------------------------------
//
// It used to be hard-coded `""`, on the reasoning that the turn record holds no assistant text and
// inventing one would be new egress. The record still holds none — it is read off `agent_end`'s
// messages and passed straight through this builder, never stored and never logged — but the row is
// what a reviewer reads, and one that showed the user's prompt and a silent assistant described half a
// conversation.

test("assistant text arrives verbatim in the assistant message", () => {
  const body = buildWith(record(), "I read the config. It sets two replicas.");

  assert.equal(body.messages[1]?.role, "assistant");
  assert.equal(body.messages[1]?.content, "I read the config. It sets two replicas.");
  assert.equal(body.messages[1]?.tool_use?.length, 1, "and the tool_use array is still there");
  assert.equal(body.assistant_truncated, undefined, "nothing was capped, so nothing is claimed");
});

test("no assistant text is the empty string, exactly as before", () => {
  for (const text of [undefined, "", 42 as unknown as string, {} as unknown as string]) {
    const body = buildWith(record(), text);
    assert.equal(body.messages[1]?.content, "", `${JSON.stringify(text)} became the content`);
    assert.equal(body.messages.length, 2, "the two-message shape the server reads is preserved");
    assert.equal(body.assistant_truncated, undefined);
  }
});

test("assistant text past MAX_ASSISTANT_CHARS keeps both ends, with the marker and a flag", () => {
  // Both ends for the same reason a command keeps both: the interesting part of a long answer is as
  // likely to be the conclusion as the opening, and a head-only cut would always lose one of them.
  const head = "HEAD_OF_THE_ANSWER";
  const tail = "TAIL_OF_THE_ANSWER";
  const text = head + "z".repeat(40_000) + tail;
  const body = buildWith(record(), text);
  const content = body.messages[1]?.content ?? "";

  assert.equal(content.length, MAX_ASSISTANT_CHARS, "capped to exactly the cap");
  assert.equal(MAX_ASSISTANT_CHARS, 16_384, "the cap is stated here so a change to it is deliberate");
  assert.ok(content.startsWith(head), "the opening survives");
  assert.ok(content.endsWith(tail), "and so does the conclusion");
  assert.ok(content.includes(COMMAND_TRUNCATION_MARKER), "spliced with the existing marker");
  assert.equal(body.assistant_truncated, true, "and the row says it is a prefix-plus-suffix");
});

test("assistant text just under the cap is sent whole and unflagged", () => {
  const text = "a".repeat(MAX_ASSISTANT_CHARS);
  const body = buildWith(record(), text);
  assert.equal(body.messages[1]?.content, text);
  assert.equal(body.assistant_truncated, undefined);
});

test("each tool_use entry is the PostToolUse shape the backend reads", () => {
  const [entry] = build(record()).messages[1]?.tool_use ?? [];

  assert.equal(entry?.type, "PostToolUse");
  assert.equal(entry?.tool_name, "read");
  assert.equal(entry?.tool_use_id, "call_1");
  assert.deepEqual(
    entry?.tool_input,
    { path: "/etc/app/config.yaml" },
    "the allowlisted input the pretool request already sent, not a second projection of it",
  );
  assert.deepEqual(entry?.tool_response, { content_sha256: "a".repeat(64), content_bytes: 812 });
});

test("a call recorded without a tool_input still sends the key, as an empty object", () => {
  // The backend's reader expects the key (`coding_tools_backfill_service.py:1207-1219`), and a call
  // that was cache-skipped or recorded before this field existed has nothing to put in it.
  const rec = record({
    tool_calls: [{ tool_name: "bash", tool_use_id: "call_1", decision: "skipped", ts: STARTED_AT }],
  });
  const [entry] = build(rec).messages[1]?.tool_use ?? [];
  assert.deepEqual(entry?.tool_input, {});
});

test("a junk tool_input degrades to an empty object rather than riding the wire", () => {
  for (const junk of ["command", 42, ["command"], null]) {
    const rec = record({
      tool_calls: [
        {
          tool_name: "bash",
          tool_use_id: "call_1",
          decision: "allow",
          ts: STARTED_AT,
          tool_input: junk as unknown as Record<string, unknown>,
        },
      ],
    });
    const [entry] = build(rec).messages[1]?.tool_use ?? [];
    assert.deepEqual(entry?.tool_input, {}, `${JSON.stringify(junk)} became the tool_input`);
  }
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
  // the assertion for `content` (which must not be). These two are the file-body keys, and they are
  // absent here because they are absent from what the decision seam recorded — the allowlist drops
  // them before either the pretool request or this row can see them.
  for (const key of ["content", "edits"]) {
    assert.equal(
      toolUse.includes(`"${key}":`),
      false,
      `tool_use[] carries a ${key} key: ${toolUse}`,
    );
  }
  assert.ok(toolUse.includes('"content_sha256":'), "the digest, by contrast, is present");
});

test("the allowlisted keys the pretool request sends ARE present in tool_use[]", () => {
  // The inverse of the assertion above, and the whole of the fix: `command`, `path` and `pattern` are
  // what the pretool check is evaluated on, so an audit row that omitted them described a tool call
  // without saying what the call was.
  const rec = record({
    tool_calls: [
      {
        tool_name: "bash",
        tool_use_id: "c1",
        decision: "allow",
        ts: STARTED_AT,
        tool_input: { command: "echo hi" },
      },
      {
        tool_name: "grep",
        tool_use_id: "c2",
        decision: "allow",
        ts: STARTED_AT + 1,
        tool_input: { pattern: "secret", path: "/src" },
      },
    ],
    results: [],
  });
  const entries = build(rec).messages[1]?.tool_use ?? [];

  assert.deepEqual(entries[0]?.tool_input, { command: "echo hi" });
  assert.deepEqual(entries[1]?.tool_input, { pattern: "secret", path: "/src" });
  const toolUse = JSON.stringify(entries);
  for (const key of ["command", "pattern", "path"]) {
    assert.ok(toolUse.includes(`"${key}":`), `tool_use[] lost the ${key} key: ${toolUse}`);
  }
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

test("tool_calls_truncated rides the body on the same present-only rule as results_truncated", () => {
  assert.equal(build(record()).tool_calls_truncated, undefined, "absent by default, never a zero");
  assert.equal(build(record({ tool_calls_truncated: 0 })).tool_calls_truncated, undefined);
  assert.equal(build(record({ tool_calls_truncated: 7 })).tool_calls_truncated, 7);
  assert.equal(build(record({ tool_calls_truncated: -4 })).tool_calls_truncated, undefined);
  assert.equal(
    build(record({ tool_calls_truncated: "lots" as unknown as number })).tool_calls_truncated,
    undefined,
  );
  // Independent of the results counter: a turn can drop calls, results, both or neither.
  const both = build(record({ tool_calls_truncated: 3, results_truncated: 9 }));
  assert.equal(both.tool_calls_truncated, 3);
  assert.equal(both.results_truncated, 9);
});

test("WR-04 a call's session_id stamp is never sent on the wire", () => {
  // It exists to attribute a record locally, not to add a field to the row. `tool_use[]` is built
  // from named fields precisely so a future addition to `TurnToolCall` cannot leak by default.
  const body = build(
    record({
      tool_calls: [
        { tool_name: "read", tool_use_id: "call_1", decision: "allow", ts: STARTED_AT, session_id: "sess-x" },
      ],
    }),
  );
  const serialised = JSON.stringify(body);
  assert.ok(!serialised.includes("sess-x"), "the per-entry stamp stays local");
  assert.ok(!serialised.includes("session_id"), serialised);
});

// ---------------------------------------------------------------------------------------------------
// Secret redaction before egress (#355 review, MEDIUM): the model often quotes what a tool returned,
// and a command can carry a bearer token. Both are scrubbed with the same `redactSecrets` the
// telemetry path uses — the session key by literal match, bearer tokens by pattern — before the cap.
// Server-side DLP scans what remains, exactly as for every other hook's turn log.
// ---------------------------------------------------------------------------------------------------

const SESSION_KEY = "unb_live_" + "0123456789abcdef";

test("the session key never rides the assistant text", () => {
  const body = buildTurnLogBody(record(), {
    cwd: CWD,
    completedAtMs: COMPLETED_AT,
    assistantText: `The config uses api_key=${SESSION_KEY} for the gateway.`,
    apiKey: SESSION_KEY,
  });

  assert.equal(body.messages[1]?.content.includes(SESSION_KEY), false);
  assert.equal(body.messages[1]?.content, "The config uses api_key=[REDACTED] for the gateway.");
});

test("a bearer token quoted by the model is redacted by pattern, key or no key", () => {
  const body = buildTurnLogBody(record(), {
    cwd: CWD,
    completedAtMs: COMPLETED_AT,
    assistantText: "It sends Authorization: Bearer sk-live-deadbeefcafe to the API.",
  });

  assert.equal(body.messages[1]?.content.includes("deadbeefcafe"), false);
  assert.match(body.messages[1]?.content ?? "", /Bearer \[REDACTED\]/);
});

test("tool_input.command is scrubbed of bearer tokens and the session key before it persists", () => {
  const rec = record({
    tool_calls: [
      {
        tool_name: "bash",
        tool_use_id: "call_curl",
        decision: "allow",
        ts: STARTED_AT + 5,
        tool_input: { command: `curl -H "Authorization: Bearer ${SESSION_KEY}" https://x.test` },
      },
    ],
  });
  const body = buildTurnLogBody(rec, { cwd: CWD, completedAtMs: COMPLETED_AT, apiKey: SESSION_KEY });
  const command = body.messages[1]?.tool_use?.[0]?.tool_input.command;

  assert.equal(typeof command, "string");
  assert.equal(String(command).includes(SESSION_KEY), false);
  // `redactSecrets`' bearer pattern is greedy to the next whitespace, so the closing quote goes with
  // the token — the URL that follows is untouched.
  assert.match(String(command), /^curl -H "Authorization: Bearer \[REDACTED\]\S* https:\/\/x\.test$/);
  // The record itself is untouched: redaction happens at the wire, not in the store.
  assert.match(String(rec.tool_calls[0]?.tool_input?.command), /deadbeef|unb_live_/);
});

test("redaction is applied before the cap, so a key straddling the splice cannot survive", () => {
  const filler = "a".repeat(MAX_ASSISTANT_CHARS);
  const body = buildTurnLogBody(record(), {
    cwd: CWD,
    completedAtMs: COMPLETED_AT,
    assistantText: `${filler}${SESSION_KEY}${filler}`,
    apiKey: SESSION_KEY,
  });

  assert.equal(body.messages[1]?.content.includes(SESSION_KEY), false);
  assert.equal(body.assistant_truncated, true);
});

test("every string leaf of a recorded MCP tool_input is scrubbed, structure intact", () => {
  // A resolved MCP call records its capped ARGUMENTS, which are free model-written text: a token can
  // sit anywhere in the structure, not just under `command`. Leaf by leaf — serialise-then-redact
  // would let the greedy bearer pattern swallow the JSON quotes around it.
  const rec = record({
    tool_calls: [
      {
        tool_name: "mcp__my-srv__create_page",
        tool_use_id: "call_mcp",
        decision: "allow",
        ts: STARTED_AT + 5,
        tool_input: {
          title: `uses ${SESSION_KEY}`,
          headers: { auth: "Bearer sk-live-deadbeefcafe" },
          list: ["plain", `key=${SESSION_KEY}`, 7, true, null],
          count: 3,
        },
      },
    ],
  });
  const body = buildTurnLogBody(rec, { cwd: CWD, completedAtMs: COMPLETED_AT, apiKey: SESSION_KEY });
  const input = body.messages[1]?.tool_use?.[0]?.tool_input;

  assert.deepStrictEqual(input, {
    title: "uses [REDACTED]",
    headers: { auth: "Bearer [REDACTED]" },
    list: ["plain", "key=[REDACTED]", 7, true, null],
    count: 3,
  });
  const wire = JSON.stringify(body);
  assert.equal(wire.includes(SESSION_KEY), false);
  assert.equal(wire.includes("deadbeefcafe"), false);
});

test("a recorded tool_input deeper than the walk cap is cut, never a throw", () => {
  let deep: Record<string, unknown> = { leaf: "bottom" };
  for (let i = 0; i < 20; i += 1) deep = { next: deep };
  const rec = record({
    tool_calls: [{ tool_name: "mcp__s__t", tool_use_id: "c", decision: "allow", ts: 1, tool_input: deep }],
  });
  const body = buildTurnLogBody(rec, { cwd: CWD, completedAtMs: COMPLETED_AT });
  const wire = JSON.stringify(body.messages[1]?.tool_use?.[0]?.tool_input);
  assert.equal(wire.includes("bottom"), false, "below the cap is dropped");
  assert.ok(wire.startsWith('{"next":{"next"'), "above it is kept");
});
