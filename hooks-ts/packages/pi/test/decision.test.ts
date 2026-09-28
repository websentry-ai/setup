// HOOK-01 — the verdict-to-pi-behaviour mapping, driven through the real core composition against
// the scripted mock gateway.
//
// The user-facing strings are asserted as LITERALS, not by importing `constants.ts`. Importing the
// constant would make the assertion self-fulfilling: a typo in the constant would silently retune
// the test instead of failing it. These strings are locked by 08-CONTEXT.md and are what the model
// and the developer actually read (§B5), so they are spelled out here on purpose.
//
// Every client is built with `timeoutMs: 50`, so the whole suite runs in milliseconds.

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../../core/src/client.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { ATTRIBUTION_SUFFIX, startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { decideToolCall } from "../src/decide.ts";
import type { DecideDeps } from "../src/decide.ts";
import { isShellCall } from "../src/narrow.ts";
import { createFakeCtx, createFakeToolCallEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtx, FakeCtxOptions } from "./helpers/fakeCtx.ts";

const TEST_KEY = "unb_test_key_1234567890";
const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";

function depsFor(api: MockApi): DecideDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS });
  return {
    checker: createPolicyChecker({
      client,
      state: createPolicyState(),
      telemetry: createTelemetry({ client, apiKey: TEST_KEY }),
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
  };
}

/** Only the policy calls; a fail-open bypass self-report also lands in `api.requests`. */
function pretoolRequests(api: MockApi): unknown[] {
  return api.requests.filter((r) => r.path === PRETOOL_PATH);
}

interface RunResult {
  result: { block?: boolean; reason?: string } | undefined;
  api: MockApi;
  ctx: FakeCtx;
}

/**
 * Start the mock in `mode`, run one bash `tool_call` through the adapter, close the mock.
 * `body` lets a caller inspect the captured wire body before teardown.
 */
async function run(
  mode: MockMode,
  opts: {
    toolName?: string;
    input?: Record<string, unknown>;
    ctx?: Partial<FakeCtxOptions>;
    /** Extra calls to make before the asserted one (used to prime `failBlock`). */
    warmups?: number;
  } = {},
): Promise<RunResult> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx(opts.ctx);
  const deps = depsFor(api);
  try {
    for (let i = 0; i < (opts.warmups ?? 0); i += 1) {
      await decideToolCall(
        createFakeToolCallEvent("bash", { command: "echo warmup" }),
        ctx,
        deps,
      );
    }
    const event = createFakeToolCallEvent(
      opts.toolName ?? "bash",
      opts.input ?? { command: "cat /etc/shadow" },
    );
    const result = await decideToolCall(event, ctx, deps);
    return { result, api, ctx };
  } finally {
    await api.close();
  }
}

test("HOOK-01 deny: the API reason is prefixed verbatim and notified as an error", async () => {
  const { result, ctx } = await run("deny");

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(ctx.notifyCalls.length, 1, "exactly one notification");
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: "Reading secrets is blocked.",
    type: "error",
  });
});

test("HOOK-01 deny with no reason: the generic string, never undefined", async () => {
  const { result } = await run("denyNoReason");

  assert.deepStrictEqual(result, { block: true, reason: "Blocked by Unbound policy." });
  assert.notEqual(result?.reason, undefined);
  assert.equal(result?.reason?.includes("undefined"), false, "no stringified undefined");
});

test("HOOK-01 deny: the attribution footer survives byte-for-byte at the end", async () => {
  const { result } = await run("attributed");

  const reason = result?.reason ?? "";
  assert.ok(reason.startsWith("Blocked by Unbound policy: "), `prefix missing in ${reason}`);
  assert.ok(reason.endsWith(ATTRIBUTION_SUFFIX), "footer must remain last");
  assert.ok(reason.endsWith("\n\nEnforced by Unbound · Trace ID abc"), "footer verbatim");
});

test("HOOK-01 deny: the block result carries no batch-termination key", async () => {
  const { result } = await run("deny");

  assert.ok(result !== undefined);
  assert.equal(Object.hasOwn(result, "terminate"), false, "Phase 8 never sets it (§A3)");
});

test("HOOK-01 allow: returns undefined and never mutates event.input", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  try {
    const event = createFakeToolCallEvent("bash", { command: "echo hi", timeout: 30 });
    const before = structuredClone(event.input);

    const result = await decideToolCall(event, ctx, depsFor(api));

    assert.equal(result, undefined);
    assert.deepStrictEqual(event.input, before, "event.input is read-only in Phase 8 (§F9)");
    assert.equal(ctx.notifyCalls.length, 0, "an allow is silent");
    assert.equal(pretoolRequests(api).length, 1);
  } finally {
    await api.close();
  }
});

test("HOOK-01 empty bash command: zero HTTP requests (§B3)", async () => {
  const { result, api } = await run("deny", { input: { command: "" } });

  assert.equal(result, undefined, "an empty command is nothing to evaluate");
  assert.equal(api.requests.length, 0, "no round trip at all");
});

test("HOOK-01 whitespace-only bash command: zero HTTP requests (§B3)", async () => {
  const { result, api } = await run("deny", { input: { command: "   " } });

  assert.equal(result, undefined);
  assert.equal(api.requests.length, 0);
});

// CR-01 — `powershell` is pi's second shell tool. It is a first-class built-in
// (`allToolNames` in `dist/core/tools/index.js:19-28`) whose input is *the same type* as bash's
// (`PowerShellToolInput = BashToolInput`, `dist/core/tools/powershell.d.ts:10`). It is merely off in
// the default active set, so `--tools` / `defaultTools` turns it on. Before these tests it narrowed
// to "not a shell call", the command never reached the wire, and every terminal policy was silently
// inapplicable on a machine configured that way.

test("HOOK-01 powershell deny: pi's other shell tool is checked exactly like bash (CR-01)", async () => {
  const { result, ctx } = await run("deny", {
    toolName: "powershell",
    input: { command: "Remove-Item -Recurse -Force C:\\src" },
  });

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Blocked by Unbound policy: Reading secrets is blocked.",
  });
  assert.equal(ctx.notifyCalls.length, 1, "exactly one notification");
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: "Reading secrets is blocked.",
    type: "error",
  });
});

test("HOOK-01 powershell: the wire body carries tool_name and the verbatim command (CR-01)", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  try {
    const result = await decideToolCall(
      createFakeToolCallEvent("powershell", { command: "Get-Content C:\\secrets.txt" }, "toolu_ps"),
      ctx,
      depsFor(api),
    );

    assert.equal(result, undefined);
    const requests = pretoolRequests(api);
    assert.equal(requests.length, 1, "a powershell call is evaluated");
    const body = api.requests[0]?.body as {
      pre_tool_use_data?: { tool_name?: string; command?: string; tool_use_id?: string };
    };
    assert.equal(body.pre_tool_use_data?.tool_name, "powershell");
    assert.equal(
      body.pre_tool_use_data?.command,
      "Get-Content C:\\secrets.txt",
      "the command must reach the gateway, not the empty string",
    );
    assert.equal(body.pre_tool_use_data?.tool_use_id, "toolu_ps");
  } finally {
    await api.close();
  }
});

test("HOOK-01 whitespace-only powershell command: zero HTTP requests (CR-01, §B3)", async () => {
  const { result, api } = await run("deny", {
    toolName: "powershell",
    input: { command: " \t " },
  });

  assert.equal(result, undefined, "an empty command is nothing to evaluate, in either shell");
  assert.equal(api.requests.length, 0, "no round trip at all");
});

test("HOOK-01 a pathless non-bash tool still sends metadata.file_path = cwd", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx({ cwd: "/tmp/project-x" });
  try {
    const result = await decideToolCall(
      createFakeToolCallEvent("grep", { pattern: "x" }),
      ctx,
      depsFor(api),
    );

    assert.equal(result, undefined);
    const requests = pretoolRequests(api);
    assert.equal(requests.length, 1, "a non-bash tool is still evaluated");
    const body = api.requests[0]?.body as {
      pre_tool_use_data?: { tool_name?: string; metadata?: Record<string, unknown> };
    };
    assert.equal(body.pre_tool_use_data?.tool_name, "grep");
    assert.equal(body.pre_tool_use_data?.metadata?.file_path, "/tmp/project-x");
  } finally {
    await api.close();
  }
});

test("HOOK-01 the wire body carries the pi identity taken from ctx", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx({ sessionId: "sess-pi-42", modelId: "claude-sonnet-4-5" });
  try {
    await decideToolCall(
      createFakeToolCallEvent("bash", { command: "ls -la" }, "toolu_xyz"),
      ctx,
      depsFor(api),
    );

    const body = api.requests[0]?.body as Record<string, unknown>;
    assert.equal(body.conversation_id, "sess-pi-42");
    assert.equal(body.model, "claude-sonnet-4-5");
    assert.equal(body.unbound_app_label, "pi");
    assert.equal(body.client_entrypoint, "pi/0.87.1");
    const data = body.pre_tool_use_data as Record<string, unknown>;
    assert.equal(data.tool_name, "bash");
    assert.equal(data.command, "ls -la");
    assert.equal(data.tool_use_id, "toolu_xyz");
  } finally {
    await api.close();
  }
});

// WR-04, second half — "nothing evaluable" replaces the bash-only empty-command skip.
//
// The API's Path-2 entry gate needs `!!command || (isValidNativeTool && !!filePath)` (§B3). A tool
// call satisfying neither is a guaranteed-allow round trip, and pi awaits every call in a batch
// serially (§F2), so each pointless trip is felt N times. Every custom/MCP tool without a `command`
// field was making exactly that trip.

test("WR-04 a custom tool with nothing evaluable makes zero HTTP requests", async () => {
  // A deny-scripted mock proves it: a request would have produced a block.
  const { result, api } = await run("deny", {
    toolName: "mcp__notion__search",
    input: { query: "quarterly numbers" },
  });

  assert.equal(result, undefined, "nothing to evaluate is nothing to ask about");
  assert.equal(api.requests.length, 0, "no round trip at all");
});

test("WR-04 a tool with an empty input object makes zero HTTP requests", async () => {
  const { result, api } = await run("deny", { toolName: "some_custom_tool", input: {} });
  assert.equal(result, undefined);
  assert.equal(api.requests.length, 0);
});

test("WR-04 a read with a path still round-trips, and so does a defaulted grep", async () => {
  const withPath = await run("deny", { toolName: "read", input: { path: "/etc/shadow" } });
  assert.equal(withPath.result?.block, true, "a native file tool with a path is evaluated");
  assert.equal(withPath.api.requests.length, 1);

  // `grep` defaults `file_path` to cwd, so it is evaluable even with no path argument.
  const pathless = await run("deny", { toolName: "grep", input: { pattern: "secret" } });
  assert.equal(pathless.result?.block, true, "a pathless search still gets a verdict");
  assert.equal(pathless.api.requests.length, 1);
});

test("WR-04 a bash call with a real command is unchanged (no regression on Phase 8)", async () => {
  const { result, api } = await run("deny", { input: { command: "cat /etc/shadow" } });
  assert.equal(result?.block, true);
  assert.equal(api.requests.length, 1);
});

// WR-07 — CLOSED BY VERIFICATION, not by a second fix. The `typeof input === "object" &&
// input !== null` guard in `narrow.ts:61-69` arrived with the CR-01 refactor in 865191b: before it,
// a `null` input dereferenced to a TypeError inside `decideToolCall`, which the outer catch swallowed
// — so the call was allowed by accident rather than by design. This pins both halves: the guard, and
// the fact that the nothing-evaluable skip now handles the same shape deliberately.

test("WR-07 a bash event with input: null is narrowed away and costs zero HTTP", async () => {
  assert.equal(isShellCall({ toolName: "bash", toolCallId: "t1", input: null }), false);
  assert.equal(isShellCall({ toolName: "bash", toolCallId: "t1", input: undefined }), false);
  assert.equal(isShellCall({ toolName: "powershell", toolCallId: "t1", input: null }), false);
  // A shell event whose `command` is not a string is equally not a shell call.
  assert.equal(isShellCall({ toolName: "bash", toolCallId: "t1", input: { command: 42 } }), false);

  const api = await startMockApi({ mode: "deny" });
  const ctx = createFakeCtx();
  try {
    let result: unknown;
    await assert.doesNotReject(async () => {
      result = await decideToolCall(
        { toolName: "bash", toolCallId: "toolu_null", input: null },
        ctx,
        depsFor(api),
      );
    }, "a null input must not reject, and must not throw into pi (which would be a block)");

    assert.equal(result, undefined, "allowed by design, not by a swallowed TypeError");
    assert.equal(api.requests.length, 0, "and without a pointless round trip");
    assert.equal(ctx.notifyCalls.length, 0);
  } finally {
    await api.close();
  }
});

// --- the decision seam: what the turn record is told --------------------------------------------
//
// `onDecision` is the turn log's only source for `tool_use[].tool_input`, and this function is the
// last scope where pi's live `event.input` exists at all. The cases below are about what leaves it:
// the allowlisted projection, never the input object.

test("onDecision carries the allowlisted input for a shell call", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  const entries: { tool_name: string; decision: string; tool_input?: Record<string, unknown> }[] = [];
  try {
    await decideToolCall(createFakeToolCallEvent("bash", { command: "echo hi" }, "toolu_seam"), ctx, {
      ...depsFor(api),
      onDecision: (entry) => entries.push(entry),
    });

    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.decision, "allow");
    assert.deepEqual(entries[0]?.tool_input, { command: "echo hi" });
  } finally {
    await api.close();
  }
});

test("onDecision carries path and pattern for a file tool, and never a file body", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  const entries: { tool_input?: Record<string, unknown> }[] = [];
  const deps = { ...depsFor(api), onDecision: (entry: { tool_input?: Record<string, unknown> }) => entries.push(entry) };
  try {
    await decideToolCall(
      createFakeToolCallEvent("grep", { pattern: "AKIA", path: "/src" }, "toolu_grep"),
      ctx,
      deps,
    );
    await decideToolCall(
      createFakeToolCallEvent("write", { path: "/src/a.ts", content: "SEAM_FILE_BODY" }, "toolu_write"),
      ctx,
      deps,
    );

    assert.deepEqual(entries[0]?.tool_input, { pattern: "AKIA", path: "/src" });
    assert.equal(entries[1]?.tool_input?.path, "/src/a.ts");
    assert.equal(Object.hasOwn(entries[1]?.tool_input ?? {}, "content"), false);
    assert.equal(
      JSON.stringify(entries).includes("SEAM_FILE_BODY"),
      false,
      "the body does not even reach the record, let alone the wire",
    );
  } finally {
    await api.close();
  }
});

test("onDecision cannot be handed pi's live input object", async () => {
  // Mutating what the seam emitted must not be able to reach `event.input`, and vice versa: the two
  // are different objects, because one is a projection of the other rather than a reference to it.
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  const entries: { tool_input?: Record<string, unknown> }[] = [];
  try {
    const event = createFakeToolCallEvent("bash", { command: "echo hi", timeout: 30 }, "toolu_alias");
    await decideToolCall(event, ctx, {
      ...depsFor(api),
      onDecision: (entry) => entries.push(entry),
    });

    assert.notEqual(entries[0]?.tool_input, event.input, "not the same object");
    assert.deepEqual(event.input, { command: "echo hi", timeout: 30 }, "and the input is untouched (§F9)");
  } finally {
    await api.close();
  }
});

test("RES-01 a remembered block-on-failure turns a failure into the unavailable block", async () => {
  // `failBlock` answers the first call with `policy_check_failure_action: 'block'`, then hangs.
  const { result } = await run("failBlock", { warmups: 1 });

  assert.deepStrictEqual(result, {
    block: true,
    reason: "Unbound policy engine unavailable — please retry",
  });
});
