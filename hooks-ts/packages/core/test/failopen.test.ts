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
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  BREAKER_CLOSED_NOTICE,
  BREAKER_OPEN_NOTICE,
  ENGINE_UNAVAILABLE_REASON,
  ERRORS_PATH,
  ERROR_CATEGORY_BLOCKED,
  ERROR_CATEGORY_BYPASS,
  MAX_REASON_CHARS,
  PRETOOL_PATH,
} from "../src/constants.ts";
import { createBreaker } from "../src/breaker.ts";
import { createApiClient } from "../src/client.ts";
import type { ApiClient, PretoolResult } from "../src/client.ts";
import { createPolicyChecker } from "../src/policy.ts";
import { createPolicyState } from "../src/policyState.ts";
import type { PolicySnapshot } from "../src/policyState.ts";
import { createTelemetry } from "../src/telemetry.ts";
import { mapResponseToOutcome, parseDecision, sanitizeReason } from "../src/verdict.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import { ATTRIBUTION_SUFFIX, startMockApi } from "./helpers/mockApi.ts";
import type { MockApi } from "./helpers/mockApi.ts";
// The repo's only pure clock (09-00); it has no imports of its own, so this borrows a fixture, not a
// dependency on the pi package.
import { createFakeClock } from "../../pi/test/helpers/fakeCtx.ts";
import { TEST_KEY } from "./helpers/testKey.ts";

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

/**
 * `U+0080-U+009F`, the C1 control block. Every one of them is non-printing, and two are sequence
 * introducers in their own right: `U+009B` is CSI (the single-character form of `ESC [`, so it
 * carries the whole ANSI repertoire without an `ESC` byte) and `U+009D` is OSC. Stripping `\x1b`
 * alone left that door open. Spelled as an arithmetic range, not pasted, for the reason above.
 */
const C1_CODE_POINTS: readonly number[] = Array.from({ length: 32 }, (_, i) => 0x80 + i);

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

test("sanitizeReason strips the C1 control block, CSI and OSC included", () => {
  // The single-character CSI. `ESC [ 2K` erases the line; `U+009B 2K` does the same thing to a
  // terminal without containing an `ESC`, so the `\x1b` case did not cover it.
  const CSI = String.fromCodePoint(0x9b);
  const OSC = String.fromCodePoint(0x9d);
  assert.equal(sanitizeReason(`Allowed${CSI}2K rm -rf /`), "Allowed2K rm -rf /");
  assert.equal(sanitizeReason(`Blocked${OSC}0;title${CSI}A`), "Blocked0;titleA");

  for (const codePoint of C1_CODE_POINTS) {
    const char = String.fromCodePoint(codePoint);
    assert.equal(sanitizeReason(`a${char}b`), "ab", `${hex(codePoint)} must not survive`);
  }
  // A reason that is nothing but C1 bytes is empty afterwards, which is `undefined` not `""`.
  assert.equal(sanitizeReason(`${CSI}${OSC}`), undefined);

  // The range stops exactly at the C1 block: U+00A0 and up are ordinary printable Unicode and are
  // not this function's business — see the preservation test below for the characters that matter.
  const nbsp = String.fromCodePoint(0x00a0);
  assert.equal(sanitizeReason(`a${nbsp}b`), `a${nbsp}b`, "U+00A0 is outside the C1 block");

  // And the gateway's attribution footer still survives a reason that tried to erase it.
  const middot = String.fromCodePoint(0x00b7);
  const footer = `\n\nEnforced by Unbound ${middot} Trace ID abc`;
  assert.equal(sanitizeReason(`Reading secrets is blocked.${CSI}1A${footer}`), `Reading secrets is blocked.1A${footer}`);
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

function checkerFor(api: MockApi, client?: Pick<ApiClient, "postPretool" | "postHookErrors">) {
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
    // WR-03: reported as a BLOCK, not as a bypass. This case previously asserted only that a report
    // happened, which let the mislabelling pass as intended behaviour.
    await sleep(60);
    const reports = errorReports(api);
    assert.equal(reports.length, 1, "the unavailable path reports the failure too");
    const entry = (reports[0]?.body as { errors?: { message?: unknown; category?: unknown }[] })
      .errors?.[0];
    assert.equal(entry?.category, ERROR_CATEGORY_BLOCKED, "a block is filed as a block");
    assert.notEqual(entry?.category, ERROR_CATEGORY_BYPASS, "and never as a bypass");
    assert.ok(
      String(entry?.message).startsWith("pi hook blocked_due_to_failure:"),
      `the Sentry fingerprint carries the honest label: ${String(entry?.message)}`,
    );
  } finally {
    await api.close();
  }
});

test("RES-01 a client that throws synchronously still yields an allow", async () => {
  // Annotated with what the checker and the reporter actually consume, not the whole `ApiClient`:
  // this double has no business knowing that a turn-log endpoint exists.
  const throwing: Pick<ApiClient, "postPretool" | "postHookErrors"> = {
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

// --- the onSync persistence seam (RES-03) ------------------------------------------------------
//
// `policy.ts` must be able to hand a policy snapshot to a persister without learning what a
// filesystem is — that purity is what makes the "client stubbed to raise synchronously" test above
// possible and what will let a future opencode adapter reuse the file untouched. So the cache write
// is an injected callback, wired by the composition root in `packages/pi/src/index.ts` (09-04).

/** A client that answers with a fixed body and never touches the network. */
function stubClient(
  body: Record<string, unknown>,
  ok = true,
): Pick<ApiClient, "postPretool" | "postHookErrors"> {
  return {
    postPretool: async () =>
      ok
        ? { ok: true, body: body as never, elapsedMs: 1 }
        : { ok: false, errorClass: "HttpStatus500", elapsedMs: 1 },
    postHookErrors: async () => true,
  };
}

function telemetryFor(client: Pick<ApiClient, "postHookErrors">) {
  return createTelemetry({ client, apiKey: TEST_KEY, now: () => FIXED_NOW });
}

test("RES-03 onSync fires exactly once per successful response, with the recorded snapshot", async () => {
  const client = stubClient({
    decision: "allow",
    tools_to_check: ["read"],
    policy_check_failure_action: "block",
  });
  const seen: PolicySnapshot[] = [];
  const checker = createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: telemetryFor(client),
    onSync: (snapshot) => {
      seen.push(snapshot);
    },
    now: () => FIXED_NOW,
  });

  assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
  assert.equal(seen.length, 1, "one response, one persist");
  assert.deepEqual(seen[0], {
    fetched_at: FIXED_NOW,
    tools_synced_at: FIXED_NOW,
    tools_to_check: ["read"],
    policy_check_failure_action: "block",
  });

  await checker.checkTool(payload(), "bash");
  assert.equal(seen.length, 2, "and once more for the second response");
});

test("RES-03 onSync uses the injected clock, so a TTL test never reads the wall clock", async () => {
  const client = stubClient({ decision: "allow", tools_to_check: [] });
  let clock = FIXED_NOW;
  const seen: PolicySnapshot[] = [];
  const checker = createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: telemetryFor(client),
    onSync: (snapshot) => {
      seen.push(snapshot);
    },
    now: () => clock,
  });

  await checker.checkTool(payload(), "bash");
  clock = FIXED_NOW + 300_001;
  await checker.checkTool(payload(), "bash");

  assert.equal(seen[0]?.tools_synced_at, FIXED_NOW);
  assert.equal(seen[1]?.tools_synced_at, FIXED_NOW + 300_001);
  // `[]` is carried through the seam as a value, not dropped as "nothing to persist".
  assert.deepEqual(seen[0]?.tools_to_check, []);
});

test("RES-03 onSync never fires on a failure — a failed check must not refresh the cache", async () => {
  const client = stubClient({}, false);
  let calls = 0;
  const checker = createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: telemetryFor(client),
    onSync: () => {
      calls += 1;
    },
    now: () => FIXED_NOW,
  });

  assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
  assert.equal(calls, 0, "a 500 taught nothing, so there is nothing to write");
});

test("RES-03 an onSync that throws changes neither the verdict nor the outcome", async () => {
  // The persister touches a filesystem, so it CAN fail (EACCES, ENOSPC, a full disk). pi turns an
  // exception out of a tool_call handler into a block, so a failed cache write must be invisible.
  const client = stubClient({ decision: "deny", reason: "Reading secrets is blocked." });
  const checker = createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: telemetryFor(client),
    onSync: () => {
      throw new Error("ENOSPC: no space left on device");
    },
    now: () => FIXED_NOW,
  });

  let outcome: unknown;
  await assert.doesNotReject(async () => {
    outcome = await checker.checkTool(payload(), "bash");
  }, "a throwing persister must not reject checkTool");
  assert.deepEqual(outcome, { kind: "deny", reason: "Reading secrets is blocked." });
});

test("RES-03 a checker with no onSync behaves exactly as before", async () => {
  const client = stubClient({ decision: "allow", tools_to_check: ["read"] });
  const state = createPolicyState();
  // The option is optional: every Phase 8 call site constructs the checker without it.
  const checker = createPolicyChecker({ client, state, telemetry: telemetryFor(client) });
  assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
  assert.deepEqual(state.getToolsToCheck(), ["read"], "the state is still recorded");
});

// --- WR-02: the breaker as `checkTool` behaviour ------------------------------------------------
//
// The state machine itself is unit-tested in `breaker.test.ts`. What matters here is the wiring: the
// gate runs BEFORE any fetch (asserted by request count, not by latency alone), the two transitions
// reach the caller's `hooks.notify` exactly once each, and a fail-CLOSED org is exempt from the whole
// mechanism (§F8) — skipping its call and allowing would invert the contract it paid for.

const pretoolCalls = (api: MockApi) => api.requests.filter((r) => r.path === PRETOOL_PATH);

interface Notice {
  message: string;
  level: "info" | "warning" | "error";
}

function breakerHarness(api: MockApi, state = createPolicyState()) {
  const clock = createFakeClock();
  const wire = createApiClient({
    baseUrl: api.url,
    apiKey: TEST_KEY,
    timeoutMs: TIMEOUT_MS,
    errorsTimeoutMs: TIMEOUT_MS,
  });
  const notices: Notice[] = [];
  const checker = createPolicyChecker({
    client: wire,
    state,
    telemetry: createTelemetry({ client: wire, apiKey: TEST_KEY, now: () => FIXED_NOW }),
    breaker: createBreaker({ now: clock.now }),
  });
  const hooks = {
    notify(message: string, level: "info" | "warning" | "error") {
      notices.push({ message, level });
    },
  };
  return {
    clock,
    notices,
    state,
    check: () => checker.checkTool(payload(), "bash", hooks),
  };
}

test("WR-02 three failures take the gateway out of circuit: the fourth call makes zero requests", async () => {
  // `hang` with a 50 ms deadline, so the contrast is visible: a real attempt costs the deadline, a
  // skipped one costs nothing.
  const api = await startMockApi({ mode: "hang" });
  try {
    const h = breakerHarness(api);
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(await h.check(), { kind: "allow" }, `failure ${i + 1} fails open`);
    }
    assert.equal(pretoolCalls(api).length, 3, "all three failures were real attempts");

    const startedAt = Date.now();
    assert.deepEqual(await h.check(), { kind: "allow" }, "the fourth call allows immediately");
    const elapsed = Date.now() - startedAt;

    assert.equal(pretoolCalls(api).length, 3, "not a fourth request — the breaker is open");
    assert.ok(elapsed < TIMEOUT_MS, `the skipped call took ${elapsed}ms, well under the deadline`);
  } finally {
    await api.close();
  }
});

test("WR-02 the open notice is byte-identical and emitted exactly once across four failures", async () => {
  const api = await startMockApi({ mode: "500" });
  try {
    const h = breakerHarness(api);
    for (let i = 0; i < 4; i += 1) await h.check();

    const opens = h.notices.filter((n) => n.message === BREAKER_OPEN_NOTICE);
    assert.equal(opens.length, 1, `exactly one open notice, got ${JSON.stringify(h.notices)}`);
    assert.equal(opens[0]?.level, "warning");
    // Spelled out as well as compared to the constant: this string is locked by 09-CONTEXT.md and a
    // typo in `constants.ts` must fail here rather than silently retune the assertion.
    assert.equal(
      BREAKER_OPEN_NOTICE,
      "Unbound policy engine unreachable — allowing tool calls for 60 s",
    );
  } finally {
    await api.close();
  }
});

test("WR-02 a recovered gateway closes the breaker with exactly one close notice", async () => {
  const api = await startMockApi({ mode: "500" });
  try {
    const h = breakerHarness(api);
    for (let i = 0; i < 3; i += 1) await h.check();
    assert.equal(pretoolCalls(api).length, 3);

    // Still open: no probe yet.
    await h.check();
    assert.equal(pretoolCalls(api).length, 3, "the window has not elapsed");

    h.clock.advance(60_001);
    api.setMode("allow");
    assert.deepEqual(await h.check(), { kind: "allow" }, "the probe goes out and succeeds");
    assert.equal(pretoolCalls(api).length, 4, "exactly one probe");

    const closes = h.notices.filter((n) => n.message === BREAKER_CLOSED_NOTICE);
    assert.equal(closes.length, 1, "one close notice");
    assert.equal(closes[0]?.level, "info");

    // Closed again: ordinary traffic flows and says nothing further.
    await h.check();
    assert.equal(pretoolCalls(api).length, 5);
    assert.equal(h.notices.length, 2, "one open, one close, nothing else");
  } finally {
    await api.close();
  }
});

test("WR-02 a fail-closed org is never disarmed by the breaker (§F8)", async () => {
  const api = await startMockApi({ mode: "hang" });
  try {
    const state = createPolicyState();
    // The last good response asked for block-on-failure. That org bought real attempts.
    state.recordSuccess({ decision: "allow", policy_check_failure_action: "block" });
    const h = breakerHarness(api, state);

    for (let i = 0; i < 4; i += 1) {
      assert.deepEqual(await h.check(), { kind: "unavailable" }, `call ${i + 1} still blocks`);
    }
    assert.equal(
      pretoolCalls(api).length,
      4,
      "four calls, four real requests — the breaker was never consulted",
    );
    assert.deepEqual(h.notices, [], "and no notice promising 60 s of allowed tool calls");
  } finally {
    await api.close();
  }
});

test("WR-02 a notify that throws changes neither the verdict nor the outcome", async () => {
  const api = await startMockApi({ mode: "500" });
  try {
    const wire = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
    const checker = createPolicyChecker({
      client: wire,
      state: createPolicyState(),
      telemetry: createTelemetry({ client: wire, apiKey: TEST_KEY, now: () => FIXED_NOW }),
      breaker: createBreaker({ now: () => FIXED_NOW }),
    });
    const hostile = {
      notify() {
        throw new Error("the TUI exploded");
      },
    };

    let outcome: unknown;
    await assert.doesNotReject(async () => {
      for (let i = 0; i < 3; i += 1) outcome = await checker.checkTool(payload(), "bash", hostile);
    }, "a notice must never be able to reject checkTool");
    assert.deepEqual(outcome, { kind: "allow" });
  } finally {
    await api.close();
  }
});

test("WR-02 hooks is optional: a checker called without it still opens the breaker", async () => {
  const api = await startMockApi({ mode: "500" });
  try {
    const wire = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
    const checker = createPolicyChecker({
      client: wire,
      state: createPolicyState(),
      telemetry: createTelemetry({ client: wire, apiKey: TEST_KEY, now: () => FIXED_NOW }),
    });
    for (let i = 0; i < 4; i += 1) {
      assert.deepEqual(await checker.checkTool(payload(), "bash"), { kind: "allow" });
    }
    // The default breaker is internally constructed, so Phase 8 call sites get the protection too.
    assert.equal(pretoolCalls(api).length, 3, "the fourth call was skipped with no adapter wiring");
  } finally {
    await api.close();
  }
});

test("RES-03 policy.ts stays free of filesystem and of throw", () => {
  const source = readFileSync(new URL("../src/policy.ts", import.meta.url), "utf8");
  assert.equal(source.includes("node:fs"), false, "the persister is injected, never imported");
  assert.equal(/^\s*throw /m.test(source), false, "an exception out of this module would be a block");
});

// --- PR #371 round 2: an oversized body is never posted --------------------------------------------

test("an oversized body is not posted: fail-open allows, fail-closed is unavailable, reported once, breaker untouched", async () => {
  const big = { pre_tool_use_data: { tool_name: "x", command: "", metadata: { blob: "b".repeat(1_000_000) } } } as never;
  for (const failureAction of ["allow", "block"] as const) {
    let posts = 0;
    const reports: { errorClass: string; blocked: boolean }[] = [];
    const state = createPolicyState();
    state.recordSuccess({ decision: "allow", policy_check_failure_action: failureAction }, Date.now());
    const checker = createPolicyChecker({
      client: {
        async postPretool() {
          posts += 1;
          return { ok: true, body: { decision: "allow" } } as never;
        },
        async postHookErrors() {
          return true;
        },
        async postTurnLog() {
          return true;
        },
      } as never,
      state,
      telemetry: {
        reportBypass: (ctx: { errorClass: string; blocked: boolean }) => reports.push(ctx),
        reportTurnLogFailure: () => {},
      } as never,
    });
    const outcome = await checker.checkTool(big, "mcp__s__t");
    assert.equal(posts, 0, "never posted — the ingress would answer 413");
    assert.deepStrictEqual(outcome, failureAction === "block" ? { kind: "unavailable" } : { kind: "allow" });
    assert.deepStrictEqual(reports.map((r) => [r.errorClass, r.blocked]), [["PayloadTooLarge", failureAction === "block"]]);
    // The breaker was not fed a failure: a normal-size call still posts.
    await checker.checkTool({ pre_tool_use_data: { tool_name: "bash", command: "ls", metadata: {} } } as never, "bash");
    assert.equal(posts, 1);
  }
});
