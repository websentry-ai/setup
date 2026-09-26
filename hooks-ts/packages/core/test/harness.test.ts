// Tests for the test harness itself.
//
// Waves 1-4 of Phase 9 assert behaviours that are only provable if the mock gateway is at least as
// strict as the real one. Three properties in particular:
//
//   * The mock models the API's Path-2 entry gate (preToolUseHandler.ts:846-861), so a file-tool
//     test that forgets to send `metadata.file_path` FAILS instead of passing vacuously against a
//     mock that allows everything.
//   * `tools_to_check` has three distinguishable states - a list, `[]` ("no file policies") and an
//     absent key ("no opinion") - because the two-timestamp policy cache treats them differently.
//   * `/v1/hooks/pi` is a real route with ok/401/hang behaviours, so the turn log can be captured.
//
// If this file goes red, every downstream Phase 9 claim built on the harness is suspect.

import test from "node:test";
import assert from "node:assert/strict";

import { startMockApi } from "./helpers/mockApi.ts";
import type { MockApi, MockMode } from "./helpers/mockApi.ts";

interface Posted {
  status: number;
  body: Record<string, unknown>;
  raw: string;
}

// Every non-hang expectation is bounded, so a mock that answers nothing fails the assertion
// instead of hanging the suite. The deliberate hang paths pass their own signal.
async function post(api: MockApi, path: string, body: unknown): Promise<Posted> {
  const res = await fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer test-key" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(3000),
  });
  const raw = await res.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    parsed = {};
  }
  return { status: res.status, body: parsed, raw };
}

/** A tool request with nothing evaluable: no command, no file_path. */
function vacuousToolRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    conversation_id: "sess-1",
    model: "auto",
    event_name: "tool_use",
    unbound_app_label: "pi",
    pre_tool_use_data: {
      tool_name: "read",
      command: "",
      metadata: { cwd: "/tmp/project" },
    },
    ...overrides,
  };
}

/** The same request with an evaluable `command`. */
function commandToolRequest(command = "cat .env"): Record<string, unknown> {
  return {
    conversation_id: "sess-1",
    model: "auto",
    event_name: "tool_use",
    unbound_app_label: "pi",
    pre_tool_use_data: {
      tool_name: "bash",
      command,
      metadata: { cwd: "/tmp/project" },
    },
  };
}

/** The same request with an evaluable `metadata.file_path` and a blank command. */
function filePathToolRequest(filePath = "/tmp/project/.env"): Record<string, unknown> {
  return {
    conversation_id: "sess-1",
    model: "auto",
    event_name: "tool_use",
    unbound_app_label: "pi",
    pre_tool_use_data: {
      tool_name: "read",
      command: "",
      metadata: { cwd: "/tmp/project", file_path: filePath },
    },
  };
}

// --- The entry gate (T-09-08) ---------------------------------------------------------------

test("entry gate: a tool request with neither command nor file_path is allowed in deny mode", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    const res = await post(api, "/v1/hooks/pretool", vacuousToolRequest());
    assert.equal(res.status, 200);
    assert.equal(res.body.decision, "allow");
    assert.equal(res.body._entry_gate, "no_evaluable_input");
    assert.equal(res.body.policy_check_failure_action, "allow");
    // The marker names the reason, so a vacuous pass is diagnosable from the captured body alone.
    assert.equal(res.body.reason, undefined);
  } finally {
    await api.close();
  }
});

test("entry gate: a blank-but-present command is still nothing evaluable", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    for (const command of ["", "   ", "\n\t"]) {
      const res = await post(
        api,
        "/v1/hooks/pretool",
        vacuousToolRequest({
          pre_tool_use_data: { tool_name: "read", command, metadata: { cwd: "/tmp/project" } },
        }),
      );
      assert.equal(res.body.decision, "allow", `command ${JSON.stringify(command)} should not be evaluable`);
      assert.equal(res.body._entry_gate, "no_evaluable_input");
    }
  } finally {
    await api.close();
  }
});

test("entry gate: a command alone passes the gate and reaches the configured mode", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    const res = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.equal(res.body.decision, "deny");
    assert.equal(res.body.reason, "Reading secrets is blocked.");
    assert.equal(res.body._entry_gate, undefined);
  } finally {
    await api.close();
  }
});

test("entry gate: a metadata.file_path alone passes the gate - this is what makes file-tool tests real", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    const withPath = await post(api, "/v1/hooks/pretool", filePathToolRequest());
    assert.equal(withPath.body.decision, "deny", "a file tool that sends file_path must be evaluated");

    // The whole point: forget the file_path and the same deny-scripted mock allows it.
    const withoutPath = await post(api, "/v1/hooks/pretool", vacuousToolRequest());
    assert.equal(withoutPath.body.decision, "allow");
    assert.equal(withoutPath.body._entry_gate, "no_evaluable_input");
  } finally {
    await api.close();
  }
});

test("entry gate: applies regardless of the configured mode, including 401", async () => {
  const modes: MockMode[] = ["deny", "ask", "approval", "401", "toolsEmpty"];
  for (const mode of modes) {
    const api = await startMockApi({ mode });
    try {
      const res = await post(api, "/v1/hooks/pretool", vacuousToolRequest());
      assert.equal(res.status, 200, `mode ${mode} must not answer the gate with a non-200`);
      assert.equal(res.body.decision, "allow", `mode ${mode} must not evaluate a vacuous request`);
      assert.equal(res.body._entry_gate, "no_evaluable_input");
    } finally {
      await api.close();
    }
  }
});

test("entry gate: does not apply to user_prompt or session_start, which carry no command by design", async () => {
  const api = await startMockApi({ mode: "deny" });
  try {
    for (const eventName of ["user_prompt", "session_start"]) {
      const res = await post(
        api,
        "/v1/hooks/pretool",
        vacuousToolRequest({
          event_name: eventName,
          pre_tool_use_data: { tool_name: "", command: "", metadata: { cwd: "/tmp/project" } },
        }),
      );
      assert.equal(res.body.decision, "deny", `${eventName} must reach the configured mode`);
      assert.equal(res.body._entry_gate, undefined, `${eventName} must not be gated`);
    }
  } finally {
    await api.close();
  }
});

// --- The three tools_to_check states (RES-03) ------------------------------------------------

test("toolsList returns a strict subset, so grep is cache-skippable and read is not", async () => {
  const api = await startMockApi({ mode: "toolsList" });
  try {
    const res = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.deepEqual(res.body.tools_to_check, ["read", "write"]);
    const tools = res.body.tools_to_check as string[];
    assert.ok(tools.includes("read"), "read must be checkable");
    assert.ok(!tools.includes("grep"), "grep must be absent so a cache-skip is observable");
    assert.equal(res.body.decision, "allow");
    assert.equal(res.body.policy_check_failure_action, "allow");
  } finally {
    await api.close();
  }
});

test("toolsEmpty, toolsOmitted and toolsList are three distinguishable states", async () => {
  const api = await startMockApi({ mode: "toolsEmpty" });
  try {
    const empty = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.ok(Array.isArray(empty.body.tools_to_check), "toolsEmpty must send the key");
    assert.equal((empty.body.tools_to_check as unknown[]).length, 0);
    assert.ok("tools_to_check" in empty.body);

    api.setMode("toolsOmitted");
    const omitted = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.equal(omitted.status, 200);
    assert.ok(!("tools_to_check" in omitted.body), "toolsOmitted must not send the key at all");

    api.setMode("toolsList");
    const list = await post(api, "/v1/hooks/pretool", commandToolRequest());

    // `[]` and an absent key must not serialise to the same bytes, or the cache cannot tell
    // "no file policies" from "no opinion" and would disable every file check for 300 s.
    assert.notEqual(JSON.stringify(empty.body), JSON.stringify(omitted.body));
    assert.notEqual(JSON.stringify(empty.body), JSON.stringify(list.body));
    assert.notEqual(JSON.stringify(omitted.body), JSON.stringify(list.body));
  } finally {
    await api.close();
  }
});

// --- The 401 mode (WR-01) --------------------------------------------------------------------

test("401 mode answers HTTP 401 with an invalidApiKey-shaped body for every pretool request", async () => {
  const api = await startMockApi({ mode: "401" });
  try {
    for (let i = 0; i < 3; i += 1) {
      const res = await post(api, "/v1/hooks/pretool", commandToolRequest());
      assert.equal(res.status, 401, `request ${i} must be rejected`);
      assert.equal(res.body.error, "invalidApiKey");
    }
    assert.equal(api.requests.length, 3, "every rejected request is still captured");
  } finally {
    await api.close();
  }
});

test("401 mode leaves /v1/hooks/errors on its own independent mode", async () => {
  // Rationale: WR-01's test asserts that ZERO errors requests are attempted once the latch trips,
  // so a 401 on that route would never be observed. setErrorsMode("500") already covers a failing
  // errors endpoint.
  const api = await startMockApi({ mode: "401", errorsMode: "ok" });
  try {
    const pretool = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.equal(pretool.status, 401);

    const errors = await post(api, "/v1/hooks/errors", { errors: [{ message: "x" }] });
    assert.equal(errors.status, 200, "the errors endpoint keeps its own mode");
    assert.equal(errors.body.success, true);
    assert.equal(errors.body.accepted, 1);
  } finally {
    await api.close();
  }
});

// --- The /v1/hooks/pi turn-log route (RES-04) ------------------------------------------------

test("POST /v1/hooks/pi is routed, recorded and answers 200 under turnLogMode ok", async () => {
  const api = await startMockApi({ mode: "allow" });
  try {
    const turn = {
      conversation_id: "sess-1",
      model: "auto",
      messages: [
        { role: "user", content: "read my env" },
        { role: "assistant", content: "done", tool_use: [{ type: "PostToolUse", tool_name: "bash" }] },
      ],
    };
    const res = await post(api, "/v1/hooks/pi", turn);
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.message, "Request logged successfully");

    const captured = api.requests.filter((r) => r.path === "/v1/hooks/pi");
    assert.equal(captured.length, 1, "the turn log must be capturable");
    assert.equal(captured[0]?.method, "POST");
    assert.deepEqual((captured[0]?.body as { messages?: unknown }).messages, turn.messages);
    assert.equal(captured[0]?.headers.authorization, "Bearer test-key");
  } finally {
    await api.close();
  }
});

test("setTurnLogMode('401') makes /v1/hooks/pi reject, without touching the pretool mode", async () => {
  const api = await startMockApi({ mode: "allow" });
  try {
    api.setTurnLogMode("401");
    const turnLog = await post(api, "/v1/hooks/pi", { conversation_id: "s" });
    assert.equal(turnLog.status, 401);
    assert.equal(turnLog.body.error, "invalidApiKey");

    const pretool = await post(api, "/v1/hooks/pretool", commandToolRequest());
    assert.equal(pretool.status, 200, "pretool keeps its own mode");
    assert.equal(pretool.body.decision, "allow");
  } finally {
    await api.close();
  }
});

test("turnLogMode 'hang' never responds, and close() still returns promptly", async () => {
  const api = await startMockApi({ mode: "allow", turnLogMode: "hang" });
  const started = Date.now();
  await assert.rejects(
    () =>
      fetch(`${api.url}/v1/hooks/pi`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ conversation_id: "s" }),
        signal: AbortSignal.timeout(200),
      }),
    "a hung turn log must only be escapable via the client's own signal",
  );
  assert.equal(api.requests.filter((r) => r.path === "/v1/hooks/pi").length, 1);

  await api.close();
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 5000, `close() must not wait on the held socket (took ${elapsed}ms)`);
});
