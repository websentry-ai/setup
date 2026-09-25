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
import { ERRORS_PATH, ERROR_CATEGORY_BYPASS, ERROR_REPORT_INTERVAL_MS } from "../src/constants.ts";
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
  opts: { errorsMode?: MockErrorsMode; apiKey?: string | undefined; intervalMs?: number } = {},
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
  return { errorClass: "TimeoutError", toolName: "bash", elapsedMs: 20_003, ...overrides };
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
