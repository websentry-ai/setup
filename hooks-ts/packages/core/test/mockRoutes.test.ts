// The mock API's routes and modes that a second adapter relies on (13-02; closes the Phase 12
// deferred items 12-04 "no opencode route test" and 12-08 "no tool-only deny mode"):
//
//   * `POST /v1/hooks/<agent>` serves exactly the agents in `TURNLOG_AGENTS` (pi and opencode) and
//     follows `turnLogMode`; anything else 404s, as an unregistered route does in production;
//   * `denyTools` denies a `tool_use` request and allows the prompt and session-start checks;
//   * the entry gate models both evaluating paths: a request with no command, no file path and no
//     MCP server is a gate allow even under `deny`, and the same request with an explicit
//     `metadata.mcp_server` is evaluated (and denied).

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import {
  DENY_TOOLS_REASON,
  ENTRY_GATE_MARKER,
  TURNLOG_AGENTS,
  hasEvaluableInput,
  startMockApi,
  turnLogAgentOf,
} from "./helpers/mockApi.ts";
import type { MockApi } from "./helpers/mockApi.ts";

let api: MockApi;

before(async () => {
  api = await startMockApi({ mode: "allow" });
});

after(async () => {
  await api.close();
});

async function post(path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

function pretoolBody(eventName: string, data: { command?: string; metadata?: Record<string, unknown> } = {}): unknown {
  return {
    conversation_id: "s1",
    model: "m",
    event_name: eventName,
    pre_tool_use_data: { tool_name: "bash", command: data.command ?? "", metadata: data.metadata ?? {} },
    messages: [],
    unbound_app_label: "opencode",
  };
}

test("TURNLOG_AGENTS serves pi and opencode; turnLogAgentOf is exact", () => {
  assert.ok(TURNLOG_AGENTS.has("pi"));
  assert.ok(TURNLOG_AGENTS.has("opencode"));
  assert.equal(turnLogAgentOf("/v1/hooks/opencode"), "opencode");
  assert.equal(turnLogAgentOf("/v1/hooks/OPENCODE"), undefined);
  assert.equal(turnLogAgentOf("/v1/hooks/opencode/x"), undefined);
  assert.equal(turnLogAgentOf("/v1/hooks/unknown"), undefined);
});

test("POST /v1/hooks/opencode and /v1/hooks/pi follow turnLogMode and are captured", async () => {
  api.setTurnLogMode("ok");
  for (const path of ["/v1/hooks/opencode", "/v1/hooks/pi"]) {
    const before = api.requests.length;
    const res = await post(path, { conversation_id: "s1", marker: path });
    assert.equal(res.status, 200, path);
    assert.equal(res.json.success, true);
    const captured = api.requests.slice(before).find((r) => r.path === path);
    assert.ok(captured, `captured ${path}`);
    assert.deepEqual((captured.body as { marker?: unknown }).marker, path);
  }
  api.setTurnLogMode("401");
  try {
    for (const path of ["/v1/hooks/opencode", "/v1/hooks/pi"]) {
      const res = await post(path, { conversation_id: "s1" });
      assert.equal(res.status, 401, path);
      assert.equal(res.json.error, "invalidApiKey");
    }
  } finally {
    api.setTurnLogMode("ok");
  }
});

test("unregistered or malformed agent routes 404", async () => {
  for (const path of ["/v1/hooks/OPENCODE", "/v1/hooks/opencode/x", "/v1/hooks/unknown"]) {
    const res = await post(path, {});
    assert.equal(res.status, 404, path);
  }
});

test("denyTools denies a tool_use bash request and allows user_prompt and session_start", async () => {
  api.setMode("denyTools");
  try {
    const tool = await post("/v1/hooks/pretool", pretoolBody("tool_use", { command: "ls" }));
    assert.equal(tool.status, 200);
    assert.equal(tool.json.decision, "deny");
    assert.equal(tool.json.reason, DENY_TOOLS_REASON);

    for (const eventName of ["user_prompt", "session_start"]) {
      const res = await post("/v1/hooks/pretool", pretoolBody(eventName));
      assert.equal(res.status, 200);
      assert.equal(res.json.decision, "allow", eventName);
    }
  } finally {
    api.setMode("allow");
  }
});

test("entry gate: no command, no file_path, no mcp_server is a gate allow even under deny", async () => {
  api.setMode("deny");
  try {
    const res = await post("/v1/hooks/pretool", pretoolBody("tool_use"));
    assert.equal(res.json.decision, "allow");
    assert.equal(res.json._entry_gate, ENTRY_GATE_MARKER);
  } finally {
    api.setMode("allow");
  }
});

test("entry gate: an explicit metadata.mcp_server is evaluated (denied under deny)", async () => {
  api.setMode("deny");
  try {
    const res = await post(
      "/v1/hooks/pretool",
      pretoolBody("tool_use", { metadata: { mcp_server: "github", mcp_tool: "create_issue" } }),
    );
    assert.equal(res.json.decision, "deny");
    assert.equal(res.json._entry_gate, undefined);
  } finally {
    api.setMode("allow");
  }
});

test("hasEvaluableInput: a blank mcp_server does not open the gate", () => {
  assert.equal(hasEvaluableInput(pretoolBody("tool_use", { metadata: { mcp_server: "  " } })), false);
  assert.equal(hasEvaluableInput(pretoolBody("tool_use", { metadata: { mcp_server: 5 } })), false);
  assert.equal(hasEvaluableInput(pretoolBody("tool_use", { metadata: { mcp_server: "github" } })), true);
});
