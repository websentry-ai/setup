// RES-02 — the 60 s rate-limited, redacted bypass report, and the in-memory last-good policy
// metadata it shares the fail-open branch with.
//
// Every bypass is an enforcement gap, so it has to be self-reported (T-08-08 makes that the audit
// trail for an accepted risk). But reporting must never become a second failure mode: the report is
// rate-limited with an injected clock, fire-and-forget, redacted, and carries only an error class,
// a tool name and an elapsed time — never the command, which may be secret-bearing (ASVS V8).

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../src/client.ts";
import {
  ERRORS_PATH,
  ERROR_CATEGORY_BLOCKED,
  ERROR_CATEGORY_BYPASS,
  ERROR_CATEGORY_TURNLOG,
  ERROR_REPORT_INTERVAL_MS,
} from "../src/constants.ts";
import { createKeyState } from "../src/keyState.ts";
import { createPolicyState } from "../src/policyState.ts";
import { createTelemetry } from "../src/telemetry.ts";
import type { BypassContext } from "../src/telemetry.ts";
import { startMockApi } from "./helpers/mockApi.ts";
import type { CapturedRequest, MockApi, MockErrorsMode } from "./helpers/mockApi.ts";

const TEST_KEY = "unb_test_key_1234567890";
const START_MS = 1_700_000_000_000;

interface Harness {
  api: MockApi;
  telemetry: ReturnType<typeof createTelemetry>;
  setClock(ms: number): void;
  errors(): CapturedRequest[];
  close(): Promise<void>;
}

async function harness(
  opts: {
    errorsMode?: MockErrorsMode;
    apiKey?: string | undefined;
    intervalMs?: number;
    isInactive?: () => boolean;
  } = {},
): Promise<Harness> {
  const api = await startMockApi({ mode: "errors", errorsMode: opts.errorsMode ?? "ok" });
  const apiKey = "apiKey" in opts ? opts.apiKey : TEST_KEY;
  let clockMs = START_MS;
  const client = createApiClient({
    baseUrl: api.url,
    apiKey: apiKey ?? "",
    errorsTimeoutMs: 50,
  });
  const telemetry = createTelemetry({
    client,
    apiKey,
    now: () => clockMs,
    intervalMs: opts.intervalMs ?? ERROR_REPORT_INTERVAL_MS,
    isInactive: opts.isInactive,
  });
  return {
    api,
    telemetry,
    setClock(ms: number) {
      clockMs = ms;
    },
    errors: () => api.requests.filter((r) => r.path === ERRORS_PATH),
    close: () => api.close(),
  };
}

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/** Waits for at least `count` error reports, then settles so a spurious extra one is still caught. */
async function settle(h: Harness, count: number, timeoutMs = 800): Promise<CapturedRequest[]> {
  const deadline = Date.now() + timeoutMs;
  while (h.errors().length < count && Date.now() < deadline) await sleep(5);
  await sleep(40);
  return h.errors();
}

function bypass(overrides: Partial<BypassContext> = {}): BypassContext {
  // `blocked: false` is the fail-OPEN case — a genuine bypass. WR-03's counterpart is `blocked: true`.
  return {
    errorClass: "TimeoutError",
    toolName: "bash",
    elapsedMs: 20_003,
    blocked: false,
    ...overrides,
  };
}

/** The one error entry a settled report produced. */
function entryOf(request: CapturedRequest | undefined): { message: string; category: string } {
  const body = request?.body as { errors?: { message?: unknown; category?: unknown }[] };
  const entry = body?.errors?.[0];
  return { message: String(entry?.message), category: String(entry?.category) };
}

test("RES-02 one bypass produces exactly one correctly-shaped report", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass());
    const reports = await settle(h, 1);
    assert.equal(reports.length, 1, "exactly one POST /v1/hooks/errors");

    const body = reports[0]?.body as {
      hook_source?: unknown;
      errors?: { message?: unknown; timestamp?: unknown; category?: unknown }[];
    };
    assert.equal(body.hook_source, "pi");
    assert.equal(body.errors?.length, 1);
    const entry = body.errors?.[0];
    assert.equal(entry?.category, ERROR_CATEGORY_BYPASS);
    assert.equal(typeof entry?.message, "string");
    assert.equal(
      new Date(String(entry?.timestamp)).toISOString(),
      new Date(START_MS).toISOString(),
      "timestamp is a valid ISO string taken from the injected clock",
    );
    // §B6: there is no `unbound_app_label` on this endpoint — the label rides `hook_source`.
    assert.equal(Object.hasOwn(body, "unbound_app_label"), false);
  } finally {
    await h.close();
  }
});

test("RES-02 the report carries the Bearer key (a keyless report would be a 401)", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass());
    const reports = await settle(h, 1);
    assert.equal(reports[0]?.headers["authorization"], `Bearer ${TEST_KEY}`);
    assert.equal(reports[0]?.method, "POST");
  } finally {
    await h.close();
  }
});

test("RES-02 at most one report per 60 s window, on the injected clock", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass());
    h.setClock(START_MS + 1_000);
    h.telemetry.reportBypass(bypass());
    h.setClock(START_MS + 59_999);
    h.telemetry.reportBypass(bypass());
    assert.equal((await settle(h, 1)).length, 1, "three bypasses inside the window => one report");

    h.setClock(START_MS + 60_001);
    h.telemetry.reportBypass(bypass());
    assert.equal((await settle(h, 2)).length, 2, "the window reopened => a second report");
  } finally {
    await h.close();
  }
});

test("RES-02 the message keeps the Sentry fingerprint stable across latencies", async () => {
  const h = await harness();
  try {
    // A long tool name pushes the elapsed-ms suffix past the 100-char fingerprint window, which is
    // the whole point of ordering the message class-first and latency-last (§B6).
    const toolName = "mcp__long_server_name__a_deliberately_long_tool_name_padding";
    h.telemetry.reportBypass(bypass({ toolName, elapsedMs: 20_003 }));
    const reports = await settle(h, 1);
    const message = String(
      (reports[0]?.body as { errors?: { message?: unknown }[] }).errors?.[0]?.message,
    );

    assert.ok(message.includes("TimeoutError"), "the error class is present");
    assert.ok(message.includes(toolName), "the tool name is present");
    assert.ok(message.endsWith("20003ms"), "elapsed ms is strictly last");
    assert.equal(
      message.slice(0, 100).includes("20003"),
      false,
      "the fingerprint window excludes the latency",
    );
  } finally {
    await h.close();
  }
});

test("RES-02 the message never leaks the key, a Bearer token or the command", async () => {
  const h = await harness();
  try {
    const leaky: BypassContext & { command: string } = {
      errorClass: `Error Bearer sk-live-deadbeef key=${TEST_KEY}`,
      toolName: "bash",
      elapsedMs: 7,
      blocked: false,
      command: "cat /etc/shadow",
    };
    h.telemetry.reportBypass(leaky);
    const reports = await settle(h, 1);
    const raw = JSON.stringify(reports[0]?.body);

    assert.equal(raw.includes(TEST_KEY), false, "the literal API key is redacted");
    assert.equal(raw.includes("sk-live-deadbeef"), false, "the Bearer token is redacted");
    assert.equal(raw.includes("/etc/shadow"), false, "the command never leaves the process");
  } finally {
    await h.close();
  }
});

test("RES-02 a failing errors endpoint is invisible to the caller", async () => {
  const h = await harness({ errorsMode: "500" });
  try {
    assert.doesNotThrow(() => h.telemetry.reportBypass(bypass()));
    assert.equal(h.telemetry.reportBypass(bypass({ toolName: "x" })), undefined);
    assert.equal((await settle(h, 1)).length, 1, "the 500 still counts as a spent window");
  } finally {
    await h.close();
  }
});

test("RES-02 a hanging errors endpoint never stalls the caller", async () => {
  const h = await harness({ errorsMode: "hang" });
  const startedAt = Date.now();
  try {
    assert.doesNotThrow(() => h.telemetry.reportBypass(bypass()));
    await settle(h, 1);
    assert.ok(Date.now() - startedAt < 1_000, "reportBypass did not block on the hung request");
  } finally {
    await h.close();
  }
});

test("RES-02 re-entrancy: a broken errors endpoint cannot trigger a second report", async () => {
  const h = await harness({ errorsMode: "500", intervalMs: 0 });
  try {
    h.telemetry.reportBypass(bypass());
    // intervalMs 0 disables the rate limiter, so only the re-entrancy guard can hold the line
    // while the first report is still in flight.
    h.telemetry.reportBypass(bypass());
    h.telemetry.reportBypass(bypass());
    assert.equal((await settle(h, 1)).length, 1, "exactly one report");
  } finally {
    await h.close();
  }
});

test("RES-02 no API key means no report at all", async () => {
  const h = await harness({ apiKey: undefined });
  try {
    h.telemetry.reportBypass(bypass());
    await sleep(60);
    assert.equal(h.errors().length, 0, "a keyless report would be a guaranteed 401");
  } finally {
    await h.close();
  }
});

// --- WR-03: a block is not a bypass ------------------------------------------------------------
//
// `message.slice(0,100)` is the Sentry fingerprint (§B6), so filing a fail-CLOSED block under
// `bypassed_due_to_failure` makes the "enforcement was silently skipped" alert fire for exactly the
// customers who paid for fail-closed and got it. An incident responder then cannot tell the two
// states apart. `category` is a free string server-side (`hookErrorHandler.ts:55-87`), so the honest
// label costs no API change.

test("WR-03 a fail-closed block is reported as blocked_due_to_failure", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass({ blocked: true, errorClass: "HttpStatus500" }));
    const reports = await settle(h, 1);
    assert.equal(reports.length, 1);

    const { message, category } = entryOf(reports[0]);
    assert.equal(category, ERROR_CATEGORY_BLOCKED);
    assert.equal(category, "blocked_due_to_failure", "the literal the server will tag and fingerprint");
    assert.ok(
      message.startsWith("pi hook blocked_due_to_failure:"),
      `the fingerprint window must carry the honest label: ${message}`,
    );
    assert.ok(message.endsWith("20003ms"), "and the elapsed-ms suffix is still strictly last");
    assert.equal(
      message.includes(ERROR_CATEGORY_BYPASS),
      false,
      "a block must not also read as a bypass",
    );
  } finally {
    await h.close();
  }
});

test("WR-03 a genuine fail-open bypass keeps bypassed_due_to_failure", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass({ blocked: false }));
    const { message, category } = entryOf((await settle(h, 1))[0]);
    assert.equal(category, ERROR_CATEGORY_BYPASS);
    assert.ok(message.startsWith("pi hook bypassed_due_to_failure:"), message);
    assert.ok(message.endsWith("20003ms"));
  } finally {
    await h.close();
  }
});

test("WR-03 the 60 s window is shared, so a block cannot outrun the rate limiter", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(bypass({ blocked: true }));
    h.setClock(START_MS + 30_000);
    h.telemetry.reportBypass(bypass({ blocked: false }));
    assert.equal((await settle(h, 1)).length, 1, "one report per window across both categories");

    h.setClock(START_MS + 60_001);
    h.telemetry.reportBypass(bypass({ blocked: true }));
    assert.equal((await settle(h, 2)).length, 2, "and the window still reopens");
  } finally {
    await h.close();
  }
});

// A lost audit row is the third thing that can happen, and it is neither of the first two. Filing a
// failed `POST /v1/hooks/pi` as `bypassed_due_to_failure` put it under the "enforcement was silently
// skipped" alert — where a turn-log route that is 404 until Phase 7 ships would bury every real
// fail-open event under noise from a route that enforces nothing.

test("a failed turn log is reported as turn_log_failed, its own category", async () => {
  const h = await harness();
  try {
    h.telemetry.reportTurnLogFailure({ errorClass: "TurnLogFailed", toolName: "agent_end", elapsedMs: 42 });
    const reports = await settle(h, 1);
    assert.equal(reports.length, 1, "exactly one POST /v1/hooks/errors");

    const { message, category } = entryOf(reports[0]);
    assert.equal(category, ERROR_CATEGORY_TURNLOG);
    assert.equal(category, "turn_log_failed", "the literal the server will tag and fingerprint");
    assert.ok(message.startsWith("pi hook turn_log_failed:"), `the fingerprint window: ${message}`);
    assert.ok(message.endsWith("42ms"), "the elapsed-ms suffix is still strictly last");
    // The whole point: neither enforcement category may appear anywhere in the report.
    assert.equal(message.includes(ERROR_CATEGORY_BYPASS), false, "never reads as a bypass");
    assert.equal(message.includes(ERROR_CATEGORY_BLOCKED), false, "and never as a block");
    const raw = JSON.stringify(reports[0]?.body);
    assert.equal(raw.includes(ERROR_CATEGORY_BYPASS), false, "not in the category field either");
    assert.equal(raw.includes(ERROR_CATEGORY_BLOCKED), false);
  } finally {
    await h.close();
  }
});

test("a turn-log report is rate-limited and redacted on the same terms as a bypass", async () => {
  const h = await harness();
  try {
    const turnLog = (errorClass = "TurnLogFailed") => ({ errorClass, toolName: "agent_end", elapsedMs: 42 });

    h.telemetry.reportTurnLogFailure(turnLog());
    assert.equal((await settle(h, 1)).length, 1);

    // One window across ALL THREE categories: the budget belongs to the endpoint, not to a category,
    // and a lost audit row must not buy a second report a bypass could not have.
    h.setClock(START_MS + 30_000);
    h.telemetry.reportTurnLogFailure(turnLog());
    h.telemetry.reportBypass(bypass());
    assert.equal((await settle(h, 1)).length, 1, "still one report in the window");

    h.setClock(START_MS + 60_001);
    h.telemetry.reportTurnLogFailure(turnLog(`Error Bearer sk-live-deadbeef key=${TEST_KEY}`));
    const reports = await settle(h, 2);
    assert.equal(reports.length, 2, "and the window reopens");
    const raw = JSON.stringify(reports[1]?.body);
    assert.equal(raw.includes(TEST_KEY), false, "the literal API key is redacted");
    assert.equal(raw.includes("sk-live-deadbeef"), false, "the Bearer token is redacted");
    assert.ok(raw.includes("turn_log_failed"), "while the category survives");
  } finally {
    await h.close();
  }
});

test("a turn-log report is silenced by a missing key and by the latch, like every other report", async () => {
  const keyState = createKeyState();
  const h = await harness({ isInactive: () => keyState.isInactive() });
  try {
    keyState.recordFailure("HttpStatus401");
    keyState.recordFailure("HttpStatus401");
    h.telemetry.reportTurnLogFailure({ errorClass: "TurnLogFailed", toolName: "agent_end", elapsedMs: 1 });
    await sleep(80);
    assert.deepEqual(h.errors(), [], "the errors endpoint uses the same rejected key (§F9)");
  } finally {
    await h.close();
  }

  const keyless = await harness({ apiKey: "" });
  try {
    keyless.telemetry.reportTurnLogFailure({ errorClass: "TurnLogFailed", toolName: "agent_end", elapsedMs: 1 });
    await sleep(80);
    assert.deepEqual(keyless.errors(), [], "no key, no report");
  } finally {
    await keyless.close();
  }
});

test("WR-03 the blocked category is redacted exactly like the bypass one", async () => {
  const h = await harness();
  try {
    h.telemetry.reportBypass(
      bypass({ blocked: true, errorClass: `Error Bearer sk-live-deadbeef key=${TEST_KEY}` }),
    );
    const raw = JSON.stringify((await settle(h, 1))[0]?.body);
    assert.equal(raw.includes(TEST_KEY), false, "the literal API key is redacted");
    assert.equal(raw.includes("sk-live-deadbeef"), false, "the Bearer token is redacted");
    assert.ok(raw.includes("blocked_due_to_failure"), "while the category survives");
  } finally {
    await h.close();
  }
});

test("WR-01 an inactive session reports nothing at all", async () => {
  // The latch and the reporter share one keyState in the composition root. This is the reporter's
  // half: `/v1/hooks/errors` authenticates with the same rejected key, so a report is pointless.
  const keyState = createKeyState();
  const h = await harness({ isInactive: () => keyState.isInactive() });
  try {
    h.telemetry.reportBypass(bypass());
    assert.equal((await settle(h, 1)).length, 1, "active: reported");

    keyState.recordFailure("HttpStatus401");
    keyState.recordFailure("HttpStatus401");
    assert.equal(keyState.isInactive(), true);

    h.setClock(START_MS + 120_000); // well outside the rate-limit window
    h.telemetry.reportBypass(bypass());
    h.telemetry.reportBypass(bypass({ blocked: true }));
    await sleep(80);
    assert.equal(h.errors().length, 1, "inactive: not one further request");
  } finally {
    await h.close();
  }
});

test("policyState remembers the last-good failure action without clobbering it", () => {
  const state = createPolicyState();
  assert.equal(state.getFailureAction(), undefined, "cold start knows nothing");

  state.recordSuccess({ decision: "allow", policy_check_failure_action: "block" });
  assert.equal(state.getFailureAction(), "block");

  // The field rides most, but not all, responses — an absent value must not erase a known one.
  state.recordSuccess({ decision: "allow" });
  assert.equal(state.getFailureAction(), "block");

  // Nor may an out-of-enum value overwrite it.
  state.recordSuccess({ decision: "allow", policy_check_failure_action: "BLOCK" });
  assert.equal(state.getFailureAction(), "block");

  state.recordSuccess({ decision: "allow", policy_check_failure_action: "allow" });
  assert.equal(state.getFailureAction(), "allow");
});

test("policyState stores tools_to_check for Phase 9 and ignores a malformed value", () => {
  const state = createPolicyState();
  assert.equal(state.getToolsToCheck(), undefined);

  state.recordSuccess({ decision: "allow", tools_to_check: ["read"] });
  assert.deepEqual(state.getToolsToCheck(), ["read"]);

  state.recordSuccess({ decision: "allow" });
  assert.deepEqual(state.getToolsToCheck(), ["read"], "an absent list does not clobber");

  state.recordSuccess({ decision: "allow", tools_to_check: "read" as unknown as string[] });
  assert.deepEqual(state.getToolsToCheck(), ["read"], "a non-array is ignored");
});
