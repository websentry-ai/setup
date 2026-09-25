// RES-01 — the fail-open matrix.
//
// pi's `emitToolCall` has no try/catch and agent-core turns a thrown handler into a **block**
// (RESEARCH §F1), so "never throws" is a functional requirement here, not hygiene. Every failure
// mode below is therefore asserted with `assert.doesNotReject` by name, not merely by inspecting
// the resolved value.
//
// Every client is constructed with `timeoutMs: 50` so the whole suite runs in milliseconds; the
// production 20 s deadline is never exercised in a unit test.

import assert from "node:assert/strict";
import test from "node:test";

import { MAX_REASON_CHARS } from "../src/constants.ts";
import { createApiClient } from "../src/client.ts";
import type { PretoolResult } from "../src/client.ts";
import { mapResponseToOutcome, parseDecision, sanitizeReason } from "../src/verdict.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import { ATTRIBUTION_SUFFIX, startMockApi } from "./helpers/mockApi.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;

function payload(): PretoolRequestBody {
  return {
    conversation_id: "sess-abc-123",
    model: "claude-sonnet-4-6",
    event_name: "tool_use",
    pre_tool_use_data: {
      tool_name: "bash",
      command: "cat /etc/shadow",
      tool_use_id: "toolu_01ABC",
      metadata: { tool_input: { command: "cat /etc/shadow" } },
    },
    messages: [],
    unbound_app_label: "pi",
    client_entrypoint: "pi/0.87.1",
  };
}

function clientFor(baseUrl: string) {
  return createApiClient({ baseUrl, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
}

/** A plain call, for the modes that are expected to answer. */
async function post(baseUrl: string): Promise<PretoolResult> {
  return clientFor(baseUrl).postPretool(payload());
}

function assertResolved(result: PretoolResult | undefined): PretoolResult {
  assert.ok(result !== undefined, "postPretool resolved with a value");
  return result;
}

test("RES-01 hang: the injected deadline aborts and postPretool resolves ok:false", async () => {
  const api = await startMockApi({ mode: "hang" });
  try {
    const client = clientFor(api.url);
    let raw: PretoolResult | undefined;
    await assert.doesNotReject(async () => {
      raw = await client.postPretool(payload());
    }, "a hung API must not reject");
    const result = assertResolved(raw);
    assert.equal(result.ok, false);
    assert.ok(!result.ok && result.errorClass.length > 0, "a non-empty telemetry label");
    assert.ok(result.elapsedMs >= TIMEOUT_MS, `elapsed ${result.elapsedMs}ms >= ${TIMEOUT_MS}ms`);
  } finally {
    await api.close();
  }
});

test("RES-01 non-2xx: a 500 resolves ok:false labelled with the status", async () => {
  const api = await startMockApi({ mode: "500" });
  try {
    const client = clientFor(api.url);
    let raw: PretoolResult | undefined;
    await assert.doesNotReject(async () => {
      raw = await client.postPretool(payload());
    }, "a 500 must not reject");
    const result = assertResolved(raw);
    assert.equal(result.ok, false);
    assert.equal(!result.ok && result.errorClass, "HttpStatus500");
  } finally {
    await api.close();
  }
});

test("RES-01 malformed JSON takes the identical branch as a network error", async () => {
  const api = await startMockApi({ mode: "malformed" });
  try {
    const client = clientFor(api.url);
    let raw: PretoolResult | undefined;
    await assert.doesNotReject(async () => {
      raw = await client.postPretool(payload());
    }, "unparseable JSON must not reject");
    const result = assertResolved(raw);
    assert.equal(result.ok, false);
    assert.equal(!result.ok && result.errorClass, "MalformedJson");
  } finally {
    await api.close();
  }
});

test("RES-01 connection refused resolves ok:false", async () => {
  const api = await startMockApi({ mode: "allow" });
  const deadUrl = api.url;
  await api.close();

  const client = clientFor(deadUrl);
  let raw: PretoolResult | undefined;
  await assert.doesNotReject(async () => {
    raw = await client.postPretool(payload());
  }, "a refused connection must not reject");
  const result = assertResolved(raw);
  assert.equal(result.ok, false);
  assert.ok(!result.ok && result.errorClass.length > 0, "a non-empty telemetry label");
  // Pins RESEARCH assumption A1 (undici nests transport failures under err.cause).
  assert.match(!result.ok ? result.errorClass : "", /^[A-Za-z0-9_]+$/);
});

test("a 200 allow resolves ok:true with the parsed body", async () => {
  const api = await startMockApi({ mode: "allow" });
  try {
    const result = await post(api.url);
    assert.equal(result.ok, true);
    assert.equal(result.ok && result.body.decision, "allow");
  } finally {
    await api.close();
  }
});

test("a 200 deny carries decision and reason through untouched", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    const result = await post(api.url);
    assert.equal(result.ok, true);
    assert.equal(result.ok && result.body.decision, "deny");
    assert.equal(result.ok && result.body.reason, "Reading secrets is blocked.");
  } finally {
    await api.close();
  }
});

test("the attribution footer survives sanitizeReason byte-for-byte", async () => {
  const api = await startMockApi({ mode: "attributed" });
  try {
    const result = await post(api.url);
    assert.ok(result.ok, "attributed mode answers 200");
    const outcome = mapResponseToOutcome(result.body);
    assert.equal(outcome.kind, "deny");
    const reason = outcome.kind === "deny" ? (outcome.reason ?? "") : "";
    assert.ok(reason.endsWith(ATTRIBUTION_SUFFIX), "the footer is preserved verbatim");
  } finally {
    await api.close();
  }
});

test("a deny with no reason keeps reason undefined (the adapter owns the fallback)", async () => {
  const api = await startMockApi({ mode: "denyNoReason" });
  try {
    const result = await post(api.url);
    assert.ok(result.ok, "denyNoReason answers 200");
    assert.equal(result.body.decision, "deny");
    assert.equal(result.body.reason, undefined);
  } finally {
    await api.close();
  }
});

test("the request carries the Bearer key, a JSON content type and the exact payload", async () => {
  const api = await startMockApi({ mode: "allow" });
  try {
    await post(api.url);
    const captured = api.requests[0];
    assert.ok(captured !== undefined, "the mock captured the request");
    assert.equal(captured.method, "POST");
    assert.equal(captured.path, "/v1/hooks/pretool");
    assert.equal(captured.headers["authorization"], `Bearer ${TEST_KEY}`);
    assert.equal(captured.headers["content-type"], "application/json");
    assert.deepEqual(captured.body, payload());
  } finally {
    await api.close();
  }
});

test("parseDecision accepts only the four enum literals (V5)", () => {
  for (const good of ["allow", "deny", "ask", "approval_required"] as const) {
    assert.equal(parseDecision(good), good);
  }
  for (const bad of ["DENY", "block", "", null, 42, {}] as const) {
    assert.equal(parseDecision(bad), undefined, `rejects ${JSON.stringify(bad)}`);
  }
});

test("sanitizeReason rejects non-strings, caps length and strips control characters", () => {
  assert.equal(sanitizeReason(42), undefined);
  assert.equal(sanitizeReason(undefined), undefined);
  assert.equal(sanitizeReason("a".repeat(5000))?.length, MAX_REASON_CHARS);
  assert.equal(sanitizeReason("a\u0007b\u001bc"), "abc");
  assert.equal(sanitizeReason("line1\nline2"), "line1\nline2");
  assert.equal(sanitizeReason("\u0000\u0007"), undefined);
});

test("mapResponseToOutcome folds ask and approval_required into one confirm outcome", () => {
  assert.deepEqual(mapResponseToOutcome({ decision: "allow" }), { kind: "allow" });
  assert.deepEqual(mapResponseToOutcome({ decision: "deny", reason: "no" }), {
    kind: "deny",
    reason: "no",
  });
  assert.deepEqual(mapResponseToOutcome({ decision: "ask", reason: "hm" }), {
    kind: "confirm",
    reason: "hm",
  });
  assert.deepEqual(mapResponseToOutcome({ decision: "approval_required" }), {
    kind: "confirm",
    reason: undefined,
  });
  // An out-of-enum decision is an allow, never a block.
  assert.deepEqual(mapResponseToOutcome({ decision: "BLOCK" }), { kind: "allow" });
  assert.deepEqual(mapResponseToOutcome(null), { kind: "allow" });
});
