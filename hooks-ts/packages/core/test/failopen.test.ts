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

import {
  ENGINE_UNAVAILABLE_REASON,
  ERRORS_PATH,
  MAX_REASON_CHARS,
} from "../src/constants.ts";
import { createApiClient } from "../src/client.ts";
import type { ApiClient, PretoolResult } from "../src/client.ts";
import { createPolicyChecker } from "../src/policy.ts";
import { createPolicyState } from "../src/policyState.ts";
import { createTelemetry } from "../src/telemetry.ts";
import { mapResponseToOutcome, parseDecision, sanitizeReason } from "../src/verdict.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import { ATTRIBUTION_SUFFIX, startMockApi } from "./helpers/mockApi.ts";
import type { MockApi } from "./helpers/mockApi.ts";

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
  // Pins RESEARCH assumption A1: undici nests transport failures under `err.cause.code` behind a
  // generic `TypeError`, so the label must surface the code. Tolerant of Node/undici churn.
  assert.match(!result.ok ? result.errorClass : "", /^(ECONNREFUSED|ENOTFOUND|UND_ERR_[A-Z_]+)$/);
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

// WR-06 — the reason may be attacker-authored (the upstream `custom_message` prompt-injection
// finding, ai-gateway#707, is still open) and it is rendered in the TUI *and* handed to the model as
// the tool-error content. ANSI was already defanged via `\x1b`; these are the Unicode equivalents,
// characters that change how the same text reads without being visible in it.
//
// Every one of them is spelled as a NUMERIC code point and built with `String.fromCodePoint`, never
// pasted verbatim: a literal would be invisible in this source, so a reviewer could not tell what is
// being asserted and a stray edit could delete a case silently.

/** Code points `sanitizeReason` must delete outright. */
const INVISIBLE_CODE_POINTS: readonly number[] = [
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0x200e, // LEFT-TO-RIGHT MARK
  0x200f, // RIGHT-TO-LEFT MARK
  0x202a, // LEFT-TO-RIGHT EMBEDDING
  0x202b, // RIGHT-TO-LEFT EMBEDDING
  0x202c, // POP DIRECTIONAL FORMATTING
  0x202d, // LEFT-TO-RIGHT OVERRIDE
  0x202e, // RIGHT-TO-LEFT OVERRIDE
  0x2060, // WORD JOINER
  0x2061, // FUNCTION APPLICATION
  0x2062, // INVISIBLE TIMES
  0x2063, // INVISIBLE SEPARATOR
  0x2064, // INVISIBLE PLUS
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
];

const RLO = String.fromCodePoint(0x202e);
const ZWSP = String.fromCodePoint(0x200b);
const LINE_SEP = String.fromCodePoint(0x2028);
const PARA_SEP = String.fromCodePoint(0x2029);

function hex(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

test("sanitizeReason strips bidi overrides, zero-width marks and the BOM (WR-06)", () => {
  // RIGHT-TO-LEFT OVERRIDE reverses the rendering of everything after it, which is enough to make a
  // deny reason read as an allow, or to forge an `Enforced by Unbound` footer.
  assert.equal(sanitizeReason(`Allowed${RLO} rm -rf /`), "Allowed rm -rf /");
  assert.equal(sanitizeReason(`bl${ZWSP}ocked`), "blocked");

  for (const codePoint of INVISIBLE_CODE_POINTS) {
    const char = String.fromCodePoint(codePoint);
    assert.equal(sanitizeReason(`a${char}b`), "ab", `${hex(codePoint)} must not survive`);
  }
});

test("sanitizeReason turns Unicode line separators into spaces, never new lines (WR-06)", () => {
  // U+2028/U+2029 are line breaks to a renderer and to the model, so they could inject what reads as
  // a fresh instruction line. They become a space rather than vanishing, so words stay separated.
  assert.equal(sanitizeReason(`Blocked.${LINE_SEP}rm -rf /`), "Blocked. rm -rf /");
  assert.equal(sanitizeReason(`Blocked.${PARA_SEP}rm -rf /`), "Blocked. rm -rf /");
  for (const codePoint of [0x2028, 0x2029]) {
    const out = sanitizeReason(`a${String.fromCodePoint(codePoint)}b`);
    assert.equal(out, "a b", `${hex(codePoint)} becomes a space`);
    assert.equal(out?.includes("\n"), false, `${hex(codePoint)} never becomes a new line`);
  }
  // The review's verified repro, which previously kept both the override and the separator.
  assert.equal(
    sanitizeReason(`Allowed by policy${RLO} ${LINE_SEP} rm -rf /`),
    "Allowed by policy   rm -rf /",
  );
});

test("sanitizeReason preserves ordinary Unicode - only the deceptive characters go (WR-06)", () => {
  // Em dash, an accented letter, CJK, and the footer's middle dot all render as themselves.
  const emDash = String.fromCodePoint(0x2014);
  const eAcute = String.fromCodePoint(0x00e9);
  const middot = String.fromCodePoint(0x00b7);
  assert.equal(
    sanitizeReason(`Blocked ${emDash} no caf${eAcute} commands`),
    `Blocked ${emDash} no caf${eAcute} commands`,
  );
  assert.equal(sanitizeReason("禁止された"), "禁止された");
  // `\n` stays load-bearing: the gateway separates its attribution footer with a blank line.
  const attributed = `Reading secrets is blocked.\n\nEnforced by Unbound ${middot} Trace ID abc`;
  assert.equal(sanitizeReason(attributed), attributed, "the footer survives byte-for-byte");
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

// --- The composed checker: checkTool() is the only function the pi adapter calls ----------------

const FIXED_NOW = 1_700_000_000_000;

function checkerFor(api: MockApi, client?: ApiClient) {
  const wire =
    client ??
    createApiClient({
      baseUrl: api.url,
      apiKey: TEST_KEY,
      timeoutMs: TIMEOUT_MS,
      errorsTimeoutMs: TIMEOUT_MS,
    });
  // A fixed clock keeps every bypass in this file inside one 60 s window.
  const telemetry = createTelemetry({ client: wire, apiKey: TEST_KEY, now: () => FIXED_NOW });
  return createPolicyChecker({ client: wire, state: createPolicyState(), telemetry });
}

const errorReports = (api: MockApi) => api.requests.filter((r) => r.path === ERRORS_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

test("checkTool maps a deny, an ask and an approval_required", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    assert.deepEqual(await checkerFor(api).checkTool(payload(), "bash"), {
      kind: "deny",
      reason: "Reading secrets is blocked.",
    });

    api.setMode("ask");
    assert.deepEqual(await checkerFor(api).checkTool(payload(), "bash"), {
      kind: "confirm",
      reason: "Unusual command.",
    });

    api.setMode("approval");
    assert.deepEqual(await checkerFor(api).checkTool(payload(), "bash"), {
      kind: "confirm",
      reason: "Needs admin approval.",
    });

    api.setMode("allow");
    assert.deepEqual(await checkerFor(api).checkTool(payload(), "bash"), { kind: "allow" });
  } finally {
    await api.close();
  }
});

test("RES-01 every failure mode fails open, reporting the bypass once per window", async () => {
  const api = await startMockApi({ mode: "hang" });
  try {
    const checker = checkerFor(api);
    for (const mode of ["hang", "500", "malformed"] as const) {
      api.setMode(mode);
      let outcome: unknown;
      await assert.doesNotReject(async () => {
        outcome = await checker.checkTool(payload(), "bash");
      }, `checkTool must not reject (mode=${mode})`);
      assert.deepEqual(outcome, { kind: "allow" }, `${mode} fails open`);
    }
    await sleep(60);
    assert.equal(errorReports(api).length, 1, "three bypasses in one 60 s window => one report");
  } finally {
    await api.close();
  }
});

test("RES-01 a refused connection fails open", async () => {
  const api = await startMockApi({ mode: "allow" });
  const deadUrl = api.url;
  await api.close();

  const checker = createPolicyChecker({
    client: createApiClient({ baseUrl: deadUrl, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS }),
    state: createPolicyState(),
    telemetry: createTelemetry({ client: { postHookErrors: async () => true } }),
  });
  let outcome: unknown;
  await assert.doesNotReject(async () => {
    outcome = await checker.checkTool(payload(), "bash");
  }, "a refused connection must not reject");
  assert.deepEqual(outcome, { kind: "allow" });
});

test("RES-01 cold start: a failure with no remembered action allows, deliberately", async () => {
  const api = await startMockApi({ mode: "hang" });
  try {
    // No success was ever recorded, so there is no `policy_check_failure_action` to honour.
    assert.deepEqual(await checkerFor(api).checkTool(payload(), "bash"), { kind: "allow" });
  } finally {
    await api.close();
  }
});

test("RES-01 a remembered policy_check_failure_action of block turns a failure unavailable", async () => {
  const api = await startMockApi({ mode: "failBlock" });
  try {
    const checker = checkerFor(api);
    // First response: allow + policy_check_failure_action 'block'. Then the mock hangs.
    assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
    assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "unavailable" });

    // The user-facing string lives in constants.ts; the adapter renders it for `unavailable`.
    assert.match(ENGINE_UNAVAILABLE_REASON, /policy engine unavailable/);

    // The enforcement outcome changed, but the failure still happened — so it is still reported.
    await sleep(60);
    assert.equal(errorReports(api).length, 1, "the unavailable path reports the bypass too");
  } finally {
    await api.close();
  }
});

test("RES-01 a client that throws synchronously still yields an allow", async () => {
  const throwing: ApiClient = {
    postPretool: () => {
      throw new Error("injected fault");
    },
    postHookErrors: async () => true,
  };
  const checker = createPolicyChecker({
    client: throwing,
    state: createPolicyState(),
    telemetry: createTelemetry({ client: throwing, apiKey: TEST_KEY }),
  });

  let outcome: unknown;
  await assert.doesNotReject(async () => {
    outcome = await checker.checkTool(payload(), "bash");
  }, "a throwing client must not reject checkTool");
  assert.deepEqual(outcome, { kind: "allow" }, "the belt to the adapter's braces");
});
