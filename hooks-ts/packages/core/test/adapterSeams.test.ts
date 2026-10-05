// Two agent-neutral seams an adapter needs from core (13-02):
//
//   * explicit MCP attribution: `PretoolPayloadInput.mcp` / `ToolCallInput.mcp` become
//     `metadata.mcp_server` / `metadata.mcp_tool`, the API's explicit-attribution contract (PLAT-12).
//     Core never infers them from a tool name. A call with no command and no file path but a valid
//     MCP server is evaluated, not skipped as nothing-evaluable.
//   * per-profile extra tool-input keys: `AgentProfile.extraToolInputKeys` widens what one agent's
//     tool input forwards, with the same caps; a profile that declares none is byte-identical to
//     today. The global `TOOL_INPUT_ALLOWLIST` is not touched.

import assert from "node:assert/strict";
import test from "node:test";

import { MAX_MCP_NAME_CHARS, MAX_TOOL_INPUT_VALUE_BYTES } from "../src/constants.ts";
import { evaluateToolCall } from "../src/evaluate.ts";
import type { DecisionEntry, EvaluateDeps, ToolCallInput } from "../src/evaluate.ts";
import { auditToolInput, buildPretoolPayload, sanitizeToolInput } from "../src/payload.ts";
import type { PolicyChecker } from "../src/policy.ts";
import { createPolicyState } from "../src/policyState.ts";
import type { AgentProfile } from "../src/profile.ts";
import type { PretoolPayloadInput, PretoolRequestBody } from "../src/types.ts";
import type { PolicyOutcome } from "../src/verdict.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

const NOW = 1_700_000_000_000;

function payloadInput(overrides: Partial<PretoolPayloadInput> = {}): PretoolPayloadInput {
  return {
    toolName: "github_create_issue",
    command: "",
    toolUseId: "call_1",
    toolInput: { title: "x" },
    cwd: "/work/project",
    sessionId: "session-1",
    model: "model-x",
    clientEntrypoint: "agent/1.0.0",
    ...overrides,
  };
}

interface Recording extends PolicyChecker {
  payloads: PretoolRequestBody[];
}

function recordingChecker(outcome: PolicyOutcome = { kind: "allow" }): Recording {
  const payloads: PretoolRequestBody[] = [];
  return {
    payloads,
    async checkTool(payload) {
      payloads.push(payload);
      return outcome;
    },
  };
}

function deps(checker: PolicyChecker, overrides: Partial<EvaluateDeps> = {}): EvaluateDeps {
  return {
    checker,
    profile: TEST_PROFILE,
    entrypoint: "agent/1.0.0",
    state: createPolicyState(),
    now: () => NOW,
    deadlineMs: 2_000,
    ...overrides,
  };
}

function mcpCall(overrides: Omit<Partial<ToolCallInput>, "mcp"> & { mcp?: unknown } = {}): ToolCallInput {
  return {
    toolName: "github_create_issue",
    toolCallId: "call_1",
    command: "",
    toolInput: { title: "x" },
    cwd: "/work/project",
    sessionId: "session-1",
    model: "model-x",
    ...overrides,
  } as ToolCallInput;
}

function metadataOf(body: PretoolRequestBody): Record<string, unknown> {
  return body.pre_tool_use_data.metadata;
}

/** An object whose every property read throws. */
function throwingProxy(): object {
  return new Proxy({}, {
    get() {
      throw new Error("hostile getter");
    },
  });
}

// --- Test 1: explicit attribution on the payload ------------------------------------------------

test("buildPretoolPayload: mcp {server, tool} becomes metadata.mcp_server / metadata.mcp_tool", () => {
  const body = buildPretoolPayload(payloadInput({ mcp: { server: "github", tool: "create_issue" } }), TEST_PROFILE);
  assert.equal(metadataOf(body).mcp_server, "github");
  assert.equal(metadataOf(body).mcp_tool, "create_issue");
});

test("buildPretoolPayload: without mcp, no MCP key exists and the body is unchanged", () => {
  const without = buildPretoolPayload(payloadInput(), TEST_PROFILE);
  assert.equal("mcp_server" in metadataOf(without), false);
  assert.equal("mcp_tool" in metadataOf(without), false);
  const withMcp = buildPretoolPayload(payloadInput({ mcp: { server: "github", tool: "create_issue" } }), TEST_PROFILE);
  const stripped = structuredClone(withMcp);
  delete stripped.pre_tool_use_data.metadata.mcp_server;
  delete stripped.pre_tool_use_data.metadata.mcp_tool;
  assert.deepEqual(stripped, without);
  // The existing keys keep their order: the MCP keys only ever append.
  assert.deepEqual(Object.keys(metadataOf(withMcp)).slice(0, 2), Object.keys(metadataOf(without)));
});

// --- Test 2: validation -------------------------------------------------------------------------

test("buildPretoolPayload: a blank, non-string or over-length server sends no MCP key", () => {
  const long = "s".repeat(MAX_MCP_NAME_CHARS + 1);
  for (const server of ["", "   ", 5, null, long] as unknown[]) {
    const body = buildPretoolPayload(
      payloadInput({ mcp: { server, tool: "create_issue" } as unknown as { server: string; tool: string } }),
      TEST_PROFILE,
    );
    assert.equal("mcp_server" in metadataOf(body), false, `server=${String(server).slice(0, 10)}`);
    assert.equal("mcp_tool" in metadataOf(body), false);
  }
});

test("buildPretoolPayload: a blank or over-length tool sends only mcp_server; names are dropped, never truncated", () => {
  for (const tool of ["", "  ", "t".repeat(MAX_MCP_NAME_CHARS + 1)]) {
    const body = buildPretoolPayload(payloadInput({ mcp: { server: "github", tool } }), TEST_PROFILE);
    assert.equal(metadataOf(body).mcp_server, "github");
    assert.equal("mcp_tool" in metadataOf(body), false);
  }
  const exact = "t".repeat(MAX_MCP_NAME_CHARS);
  const body = buildPretoolPayload(payloadInput({ mcp: { server: "github", tool: exact } }), TEST_PROFILE);
  assert.equal(metadataOf(body).mcp_tool, exact);
});

// --- Test 3: the nothing-evaluable rule ---------------------------------------------------------

test("evaluateToolCall: a pure MCP call (no command, no file path) is checked, carrying both keys", async () => {
  const checker = recordingChecker();
  const verdict = await evaluateToolCall(mcpCall({ mcp: { server: "github", tool: "x" } }), deps(checker));
  assert.deepEqual(verdict, { kind: "allow" });
  assert.equal(checker.payloads.length, 1);
  assert.equal(metadataOf(checker.payloads[0]!).mcp_server, "github");
  assert.equal(metadataOf(checker.payloads[0]!).mcp_tool, "x");
});

test("evaluateToolCall: a pure MCP call can be denied", async () => {
  const checker = recordingChecker({ kind: "deny", reason: "no" });
  const verdict = await evaluateToolCall(mcpCall({ mcp: { server: "github", tool: "x" } }), deps(checker));
  assert.deepEqual(verdict, { kind: "deny", reason: "no" });
});

test("evaluateToolCall: the same call without mcp is skipped with zero checker calls", async () => {
  const checker = recordingChecker();
  const verdict = await evaluateToolCall(mcpCall(), deps(checker));
  assert.deepEqual(verdict, { kind: "skip", why: "nothing-evaluable" });
  assert.equal(checker.payloads.length, 0);
});

test("evaluateToolCall: sendUnattributed sends the bare call with the raw tool name and no MCP keys", async () => {
  const checker = recordingChecker({ kind: "deny", reason: "no" });
  const verdict = await evaluateToolCall(
    { ...mcpCall(), toolName: "runtime_added_tool", sendUnattributed: true },
    deps(checker),
  );
  assert.deepEqual(verdict, { kind: "deny", reason: "no" });
  assert.equal(checker.payloads.length, 1);
  const body = checker.payloads[0]!;
  assert.equal(body.pre_tool_use_data.tool_name, "runtime_added_tool");
  assert.equal(body.pre_tool_use_data.command, "");
  assert.equal("mcp_server" in metadataOf(body), false);
  assert.equal("mcp_tool" in metadataOf(body), false);
});

test("evaluateToolCall: sendUnattributed with an over-length server still sends, without MCP keys", async () => {
  const checker = recordingChecker();
  const long = "s".repeat(MAX_MCP_NAME_CHARS + 1);
  const verdict = await evaluateToolCall(
    { ...mcpCall({ mcp: { server: long, tool: "x" } }), sendUnattributed: true },
    deps(checker),
  );
  assert.deepEqual(verdict, { kind: "allow" });
  assert.equal(checker.payloads.length, 1);
  assert.equal("mcp_server" in metadataOf(checker.payloads[0]!), false);
});

test("evaluateToolCall: only sendUnattributed === true lifts the nothing-evaluable gate", async () => {
  for (const flag of [false, 1, "true", null, undefined]) {
    const checker = recordingChecker();
    const verdict = await evaluateToolCall({ ...mcpCall(), sendUnattributed: flag } as ToolCallInput, deps(checker));
    assert.deepEqual(verdict, { kind: "skip", why: "nothing-evaluable" }, String(flag));
    assert.equal(checker.payloads.length, 0);
  }
});

// --- Test 4: hostile mcp values -----------------------------------------------------------------

test("evaluateToolCall: an unusable mcp value is treated as absent and the promise resolves", async () => {
  for (const mcp of [null, 5, "github", throwingProxy(), { server: 5 }, { server: "", tool: "x" }]) {
    const checker = recordingChecker();
    const verdict = await evaluateToolCall(mcpCall({ mcp }), deps(checker));
    assert.deepEqual(verdict, { kind: "skip", why: "nothing-evaluable" });
    assert.equal(checker.payloads.length, 0);
  }
});

test("evaluateToolCall: a hostile mcp on a shell call does not stop the check", async () => {
  const checker = recordingChecker();
  const verdict = await evaluateToolCall(
    mcpCall({ toolName: "bash", command: "ls", toolInput: { command: "ls" }, mcp: throwingProxy() }),
    deps(checker),
  );
  assert.deepEqual(verdict, { kind: "allow" });
  assert.equal(checker.payloads.length, 1);
  assert.equal("mcp_server" in metadataOf(checker.payloads[0]!), false);
});

// --- Test 5: per-profile extra tool-input keys ----------------------------------------------------

const INCLUDE_PROFILE: AgentProfile = Object.freeze({ ...TEST_PROFILE, extraToolInputKeys: ["include"] });

test("extraToolInputKeys: a profile that declares include forwards it", () => {
  const body = buildPretoolPayload(
    payloadInput({ toolName: "grep", toolInput: { pattern: "TODO", include: "*.ts" } }),
    INCLUDE_PROFILE,
  );
  assert.deepEqual(metadataOf(body).tool_input, { pattern: "TODO", include: "*.ts" });
});

test("extraToolInputKeys: the same per-value cap and _truncated marker apply", () => {
  const long = "a".repeat(MAX_TOOL_INPUT_VALUE_BYTES + 10);
  const out = sanitizeToolInput({ include: long }, ["include"]);
  assert.equal(out.include, "a".repeat(MAX_TOOL_INPUT_VALUE_BYTES));
  assert.equal(out._truncated, true);
  assert.equal(sanitizeToolInput({ include: { nested: true } }, ["include"])._dropped, true);
});

test("extraToolInputKeys: TEST_PROFILE (none declared) drops include with _dropped exactly as today", () => {
  const body = buildPretoolPayload(
    payloadInput({ toolName: "grep", toolInput: { pattern: "TODO", include: "*.ts" } }),
    TEST_PROFILE,
  );
  assert.deepEqual(metadataOf(body).tool_input, { pattern: "TODO", _dropped: true });
  assert.deepEqual(sanitizeToolInput({ pattern: "TODO", include: "*.ts" }), { pattern: "TODO", _dropped: true });
});

test("extraToolInputKeys: the audit projection equals the request projection", async () => {
  const decisions: DecisionEntry[] = [];
  const checker = recordingChecker();
  await evaluateToolCall(
    mcpCall({ toolName: "grep", toolInput: { pattern: "TODO", include: "*.ts", content: "body" } }),
    deps(checker, { profile: INCLUDE_PROFILE, onDecision: (entry) => decisions.push(entry) }),
  );
  assert.equal(checker.payloads.length, 1);
  assert.equal(decisions.length, 1);
  assert.deepEqual(decisions[0]!.tool_input, metadataOf(checker.payloads[0]!).tool_input);
  assert.deepEqual(decisions[0]!.tool_input, { pattern: "TODO", include: "*.ts", _dropped: true });
  assert.deepEqual(auditToolInput({ include: "*.ts" }, "", ["include"]), { include: "*.ts" });
});

// --- Test 6: an unreadable declaration is no declaration ----------------------------------------

test("extraToolInputKeys: a throwing getter or non-string members behave as none declared", async () => {
  const throwing = Object.defineProperty({ ...TEST_PROFILE }, "extraToolInputKeys", {
    get() {
      throw new Error("hostile");
    },
  }) as AgentProfile;
  const nonStrings = { ...TEST_PROFILE, extraToolInputKeys: [5, null, { a: 1 }] as unknown as string[] };
  const input = payloadInput({ toolName: "grep", toolInput: { pattern: "TODO", include: "*.ts" } });
  for (const profile of [throwing, nonStrings]) {
    assert.deepEqual(metadataOf(buildPretoolPayload(input, profile)).tool_input, { pattern: "TODO", _dropped: true });
    const checker = recordingChecker();
    const verdict = await evaluateToolCall(
      mcpCall({ toolName: "grep", toolInput: { pattern: "TODO", include: "*.ts" } }),
      deps(checker, { profile }),
    );
    assert.deepEqual(verdict, { kind: "allow" });
    assert.deepEqual(metadataOf(checker.payloads[0]!).tool_input, { pattern: "TODO", _dropped: true });
  }
  assert.deepEqual(sanitizeToolInput({ include: "x" }, throwingProxy() as unknown as string[]), { _dropped: true });
});
