// RES-04 at the pi boundary, against the real mock `/v1/hooks/pi` route.
//
// The load-bearing case is the timing one. `AC/dist/types.d.ts:418-421`: "`agent_end` is the last
// event emitted for a run, but awaited `Agent.subscribe()` listeners for that event are still part of
// run settlement. The agent becomes idle only after those listeners finish." So an awaited 10 s POST
// makes the agent look busy for 10 s after every single turn. The handler is measured against a
// hanging endpoint and must return in milliseconds.
//
// The second is the double-fire case. `agent_end` fires again on retries, on
// `stopReason: "error" | "aborted"`, and for extension-initiated prompts (§F3) — so the record is
// cleared on POST and an empty turn is never sent.

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../../core/src/client.ts";
import { ERRORS_PATH, ERROR_CATEGORY_TURNLOG, TURNLOG_PATH } from "../../core/src/constants.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { createTurnStore } from "../../core/src/turn.ts";
import type { TurnStore } from "../../core/src/turn.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { handleAgentEnd } from "../src/agentEnd.ts";
import { decideToolCall } from "../src/decide.ts";
import { createFakeAgentEndEvent, createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const MARKER = "PRIVATE_KEY_BEGIN-never-posted";
/** Well under the real 10 s deadline, so the abort is observable inside a test run. */
const SHORT_TIMEOUT_MS = 150;

const turnLogs = (api: MockApi) => api.requests.filter((r) => r.path === TURNLOG_PATH);
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

function client(api: MockApi, timeoutMs?: number) {
  return createApiClient({
    baseUrl: api.url,
    apiKey: TEST_KEY,
    ...(timeoutMs === undefined ? {} : { turnLogTimeoutMs: timeoutMs }),
  });
}

/** A store holding one prompt, one allowed tool call and one hashed result. */
function primedStore(): TurnStore {
  const store = createTurnStore();
  store.recordPrompt("summarise the config", "sess-agentend", 1_000);
  store.recordToolCall(
    {
      tool_name: "read",
      tool_use_id: "call_1",
      decision: "allow",
      // What the decision seam would have handed over: `auditToolInput`'s output, already allowlisted.
      tool_input: { path: "/srv/app/config.yaml" },
    },
    "sess-agentend",
    1_001,
  );
  store.recordResult({
    tool_name: "read",
    tool_use_id: "call_1",
    is_error: false,
    content_sha256: "e".repeat(64),
    content_bytes: 128,
  });
  return store;
}

test("a finished turn posts once to /v1/hooks/pi with a Bearer key", async () => {
  const api = await startMockApi();
  try {
    const store = primedStore();
    const result = handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
      client: client(api),
      store,
      now: () => 5_000,
    });

    assert.strictEqual(result, undefined, "the handler answers nothing, synchronously");
    await sleep(120);

    const posts = turnLogs(api);
    assert.equal(posts.length, 1, `expected one turn log, got ${posts.length}`);
    assert.equal(posts[0]?.method, "POST");
    assert.equal(posts[0]?.headers["authorization"], `Bearer ${TEST_KEY}`, "401 without it (§B1)");
    assert.equal(posts[0]?.headers["content-type"], "application/json");
  } finally {
    await api.close();
  }
});

test("the posted model is auto even when ctx carries a real model id", async () => {
  const api = await startMockApi();
  try {
    const ctx = createFakeCtx({ modelId: "openrouter/openai/gpt-4.1-nano" });
    handleAgentEnd(createFakeAgentEndEvent([]), ctx, {
      client: client(api),
      store: primedStore(),
      now: () => 5_000,
    });
    await sleep(120);

    const body = turnLogs(api)[0]?.body as { model?: string } | undefined;
    assert.equal(body?.model, "auto", "a real id means Model Not found and no row at all (§B3)");
    assert.equal(ctx.model?.id, "openrouter/openai/gpt-4.1-nano", "the real id was available");
  } finally {
    await api.close();
  }
});

test("the posted body carries the prompt, the tool call and the hashes — and no raw output", async () => {
  const api = await startMockApi();
  try {
    const store = createTurnStore();
    store.recordPrompt("read the deploy key", "sess-marker", 1_000);
    store.recordToolCall(
      { tool_name: "read", tool_use_id: "call_1", decision: "allow", tool_input: { path: "/srv/id_rsa" } },
      "sess-marker",
      1_001,
    );
    // What a real handler would have hashed; the marker is what must NOT travel.
    store.recordResult({
      tool_name: "read",
      tool_use_id: "call_1",
      is_error: false,
      content_sha256: "f".repeat(64),
      content_bytes: Buffer.byteLength(MARKER, "utf8"),
    });

    handleAgentEnd(createFakeAgentEndEvent([{ role: "assistant", content: MARKER }]), createFakeCtx(), {
      client: client(api),
      store,
      now: () => 9_000,
    });
    await sleep(120);

    const serialised = JSON.stringify(api.requests);
    assert.equal(serialised.includes(MARKER), false, "no raw output marker anywhere in any request");

    const body = turnLogs(api)[0]?.body as {
      conversation_id?: string;
      messages?: { role: string; content: string; tool_use?: Record<string, unknown>[] }[];
    };
    assert.equal(body.conversation_id, "sess-marker");
    assert.equal(body.messages?.[0]?.content, "read the deploy key");
    const entries = body.messages?.[1]?.tool_use ?? [];
    assert.equal(entries.length, 1);
    assert.deepEqual(
      entries[0]?.tool_input,
      { path: "/srv/id_rsa" },
      "the allowlisted input the pretool check already carried — the row has to say what was read",
    );
    assert.deepEqual(entries[0]?.tool_response, {
      content_sha256: "f".repeat(64),
      content_bytes: Buffer.byteLength(MARKER, "utf8"),
    });
  } finally {
    await api.close();
  }
});

test("no tool_use entry carries a content or edits key, and the allowlisted keys are there", async () => {
  const api = await startMockApi();
  try {
    const store = createTurnStore();
    store.recordPrompt("rewrite the config", "sess-keys", 1_000);
    // A shell call and a `write`, recorded exactly as the seam records them: the `write`'s 50 KB body
    // never reached `auditToolInput`'s output, so it cannot reach this row either.
    store.recordToolCall(
      { tool_name: "bash", tool_use_id: "c1", decision: "allow", tool_input: { command: "echo hi" } },
      "sess-keys",
      1_001,
    );
    store.recordToolCall(
      {
        tool_name: "write",
        tool_use_id: "c2",
        decision: "allow",
        tool_input: { path: "/srv/app/config.yaml", _dropped: true },
      },
      "sess-keys",
      1_002,
    );

    handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
      client: client(api),
      store,
      now: () => 5_000,
    });
    await sleep(120);

    const body = turnLogs(api)[0]?.body as { messages?: { tool_use?: unknown }[] };
    const toolUse = JSON.stringify(body.messages?.[1]?.tool_use);
    for (const key of ["content", "edits"]) {
      assert.equal(toolUse.includes(`"${key}":`), false, `${key} came back into the body: ${toolUse}`);
    }
    for (const key of ["command", "path"]) {
      assert.ok(toolUse.includes(`"${key}":`), `${key} is missing from the body: ${toolUse}`);
    }
  } finally {
    await api.close();
  }
});

test("a 50 KB write body appears nowhere in the request, path only", async () => {
  // End to end through the real seam rather than a hand-written record: `decideToolCall` is what
  // projects pi's live `event.input`, so this is the case that proves the allowlist is on the path
  // between a `write` and the turn log.
  const api = await startMockApi({ mode: "allow" });
  try {
    const store = createTurnStore();
    const bodyText = "WRITE_BODY_MARKER_" + "x".repeat(50_000);
    await decideToolCall(
      createFakeToolCallEvent("write", { path: "/srv/app/config.yaml", content: bodyText }, "call_w"),
      createFakeCtx({ sessionId: "sess-write" }),
      {
        checker: createPolicyChecker({
          client: client(api),
          state: createPolicyState(),
          telemetry: createTelemetry({ client: client(api), apiKey: TEST_KEY }),
        }),
        apiKey: TEST_KEY,
        entrypoint: "pi/0.87.1",
        onDecision: (entry) => store.recordToolCall(entry, "sess-write", 1_001),
      },
    );

    handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
      client: client(api),
      store,
      now: () => 5_000,
    });
    await sleep(120);

    const entries =
      (turnLogs(api)[0]?.body as { messages?: { tool_use?: Record<string, unknown>[] }[] }).messages?.[1]
        ?.tool_use ?? [];
    const toolInput = entries[0]?.tool_input as Record<string, unknown>;
    assert.equal(toolInput.path, "/srv/app/config.yaml", "the path is what the row needs");
    assert.equal(Object.hasOwn(toolInput, "content"), false);

    const serialised = JSON.stringify(api.requests);
    assert.equal(serialised.includes("WRITE_BODY_MARKER_"), false, "not in the turn log, not in the check");
    assert.equal(serialised.includes("xxxxxxxxxx"), false, "nor a slice of it");
  } finally {
    await api.close();
  }
});

// --- the reason this handler exists the way it does ----------------------------------------------

test("the handler returns in under 50 ms against a hanging endpoint (T-09-22)", async () => {
  const api = await startMockApi({ turnLogMode: "hang" });
  try {
    const startedAt = Date.now();
    const result = handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
      client: client(api, SHORT_TIMEOUT_MS),
      store: primedStore(),
      now: () => 5_000,
    });
    const elapsed = Date.now() - startedAt;

    assert.strictEqual(result, undefined);
    assert.ok(elapsed < 50, `the handler took ${elapsed}ms — run settlement waits on it (§F2)`);

    // And the request itself is bounded: the socket is aborted, not left open for the process life.
    await sleep(SHORT_TIMEOUT_MS + 120);
    assert.equal(turnLogs(api).length, 1, "the attempt was made");
  } finally {
    await api.close();
  }
});

test("a hanging endpoint produces no notice and no exception", async () => {
  const api = await startMockApi({ turnLogMode: "hang" });
  try {
    const ctx = createFakeCtx();
    await assert.doesNotReject(async () => {
      handleAgentEnd(createFakeAgentEndEvent([]), ctx, {
        client: client(api, SHORT_TIMEOUT_MS),
        store: primedStore(),
        now: () => 5_000,
      });
      await sleep(SHORT_TIMEOUT_MS + 120);
    });
    assert.deepEqual(ctx.notifyCalls, [], "a failed turn log is not the developer's problem");
  } finally {
    await api.close();
  }
});

test("a 401 changes nothing observable", async () => {
  const api = await startMockApi({ turnLogMode: "401" });
  try {
    const ctx = createFakeCtx();
    const store = primedStore();
    const result = handleAgentEnd(createFakeAgentEndEvent([]), ctx, {
      client: client(api),
      store,
      now: () => 5_000,
    });
    await sleep(140);

    assert.strictEqual(result, undefined);
    assert.deepEqual(ctx.notifyCalls, []);
    assert.equal(store.isEmpty(), true, "the record is cleared whether or not the post succeeded");
  } finally {
    await api.close();
  }
});

test("an empty turn produces zero requests", async () => {
  const api = await startMockApi();
  try {
    const result = handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
      client: client(api),
      store: createTurnStore(),
      now: () => 5_000,
    });
    await sleep(120);

    assert.strictEqual(result, undefined);
    assert.equal(api.requests.length, 0, "pi fires agent_end for runs we have nothing to say about");
  } finally {
    await api.close();
  }
});

test("a second agent_end in the same prompt does not re-post the same content (§F3)", async () => {
  const api = await startMockApi();
  try {
    const store = primedStore();
    const deps = { client: client(api), store, now: () => 5_000 };

    handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), deps);
    await sleep(120);
    assert.equal(turnLogs(api).length, 1);

    // The retry: same prompt, same run, a second agent_end.
    handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), deps);
    await sleep(120);
    assert.equal(turnLogs(api).length, 1, "the record was taken, so there is nothing left to send");
  } finally {
    await api.close();
  }
});

test("a failed post reports at most one telemetry error and never notifies", async () => {
  const api = await startMockApi({ turnLogMode: "hang" });
  try {
    const ctx = createFakeCtx();
    const reported: { errorClass: string; toolName: string }[] = [];
    const telemetry = {
      // NOT `reportBypass`: a lost audit row is not a skipped policy check, and the two share the
      // Sentry alert if they share the category. `agentEnd.ts` cannot even reach `reportBypass` now —
      // its `telemetry` is typed to this one method.
      reportTurnLogFailure(entry: { errorClass: string; toolName: string; elapsedMs: number }) {
        reported.push({ errorClass: entry.errorClass, toolName: entry.toolName });
      },
    };

    for (let i = 0; i < 3; i += 1) {
      const store = primedStore();
      handleAgentEnd(createFakeAgentEndEvent([]), ctx, {
        client: client(api, SHORT_TIMEOUT_MS),
        store,
        telemetry,
        now: () => 5_000,
      });
      await sleep(SHORT_TIMEOUT_MS + 80);
    }

    assert.deepEqual(ctx.notifyCalls, [], "never a notice");
    assert.ok(reported.length >= 1, "a silently failing audit trail is worse than a noisy one");
    assert.equal(reported[0]?.errorClass, "TurnLogFailed");
    // Rate limiting itself is `telemetry.ts`'s job and tested there; this asserts the label.
    assert.equal(reported[0]?.toolName, "agent_end");
  } finally {
    await api.close();
  }
});

test("a failed turn log reaches /v1/hooks/errors as turn_log_failed, once", async () => {
  // End to end through the REAL reporter, because the category is the whole point: filed as
  // `bypassed_due_to_failure` this fired the "enforcement was silently skipped" alert, so a turn-log
  // route that 404s until Phase 7 ships would bury every genuine fail-open event under it.
  //
  // `hang` and `401` are the two turn-log failure modes the mock scripts; `postTurnLog` answers a
  // boolean for every non-ok response, so any 4xx/5xx takes this same path.
  for (const turnLogMode of ["hang", "401"] as const) {
    const api = await startMockApi({ turnLogMode });
    try {
      const telemetry = createTelemetry({
        client: client(api, SHORT_TIMEOUT_MS),
        apiKey: TEST_KEY,
        intervalMs: 0, // the rate limiter is `telemetry.ts`'s own test; this case is about the label
      });
      handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
        client: client(api, SHORT_TIMEOUT_MS),
        store: primedStore(),
        telemetry,
      });
      await sleep(SHORT_TIMEOUT_MS + 150);

      const reports = api.requests.filter((r) => r.path === ERRORS_PATH);
      assert.equal(reports.length, 1, `exactly one report (${turnLogMode}): ${reports.length}`);
      const entry = (reports[0]?.body as { errors?: { message?: unknown; category?: unknown }[] })
        .errors?.[0];
      assert.equal(entry?.category, ERROR_CATEGORY_TURNLOG);
      assert.equal(entry?.category, "turn_log_failed");
      assert.ok(
        String(entry?.message).startsWith("pi hook turn_log_failed:"),
        `the fingerprint window carries the honest label: ${String(entry?.message)}`,
      );
      assert.equal(
        String(entry?.message).includes("bypassed_due_to_failure"),
        false,
        "and never the fail-open one",
      );
    } finally {
      await api.close();
    }
  }
});

test("the handler survives a ctx that raises and a store that raises", async () => {
  const api = await startMockApi();
  try {
    const hostileCtx = {
      get cwd(): string {
        throw new Error("ctx exploded");
      },
      hasUI: true,
      sessionManager: { getSessionId: () => "s" },
      model: undefined,
      ui: { notify: () => {}, confirm: async () => false },
    };
    let result: unknown = "unset";
    assert.doesNotThrow(() => {
      result = handleAgentEnd(createFakeAgentEndEvent([]), hostileCtx as never, {
        client: client(api),
        store: primedStore(),
        now: () => 5_000,
      });
    });
    assert.strictEqual(result, undefined);

    const exploding = {
      take() {
        throw new Error("store on fire");
      },
    } as never;
    assert.doesNotThrow(() => {
      handleAgentEnd(createFakeAgentEndEvent([]), createFakeCtx(), {
        client: client(api),
        store: exploding,
        now: () => 5_000,
      });
    });
  } finally {
    await api.close();
  }
});
